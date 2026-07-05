"""
PhantomRecon — Raw DNS Resolver
═══════════════════════════════════════════════════════════════
A DNS client built from scratch at the packet level — no dnspython,
no external DNS library. We craft the query packet by hand (RFC 1035
section 4.1) and parse the response ourselves, including DNS name
compression (pointer following).

Why build this instead of using a library? Two reasons:
  1. Zero dependencies for a core recon function.
  2. It's genuinely useful to understand DNS at the wire level for
     a security portfolio — this is the same skill applied in
     PhantomVault's crypto internals or the Day 1 packet sniffer.

Queries a public resolver directly (stub resolver pattern) rather
than performing full recursive resolution ourselves — this is how
virtually all lightweight DNS tools work; the recursive resolver
(8.8.8.8, 1.1.1.1, etc.) does the actual walk from root servers.
"""

import socket
import struct
import random

DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

RECORD_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257,
}
RECORD_TYPE_NAMES = {v: k for k, v in RECORD_TYPES.items()}


def _encode_qname(domain: str) -> bytes:
    """example.com -> b'\\x07example\\x03com\\x00'"""
    parts = domain.strip(".").split(".")
    encoded = b"".join(bytes([len(p)]) + p.encode("ascii", errors="ignore") for p in parts if p)
    return encoded + b"\x00"


def _build_query(domain: str, record_type: int, query_id: int) -> bytes:
    # Header: ID, flags (RD=1: recursion desired), QDCOUNT=1, AN/NS/AR=0
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(domain) + struct.pack("!HH", record_type, 1)  # QTYPE, QCLASS=IN
    return header + question


def _decode_name(packet: bytes, offset: int, depth: int = 0) -> tuple:
    """
    Decode a (possibly compressed) DNS name starting at `offset`.
    Returns (name_string, new_offset_after_name).
    Handles pointer compression (RFC 1035 §4.1.4): a length byte with
    its top 2 bits set (0xC0) means "the rest of this name is at the
    14-bit offset formed by the remaining 6 bits + the next byte."
    """
    if depth > 20:  # guard against malicious/malformed pointer loops
        return "", offset

    labels = []
    original_offset = None

    while True:
        if offset >= len(packet):
            break
        length_byte = packet[offset]

        if length_byte == 0:
            offset += 1
            break

        if (length_byte & 0xC0) == 0xC0:  # compression pointer
            if offset + 1 >= len(packet):
                break
            pointer = ((length_byte & 0x3F) << 8) | packet[offset + 1]
            if original_offset is None:
                original_offset = offset + 2
            sub_name, _ = _decode_name(packet, pointer, depth + 1)
            if sub_name:
                labels.append(sub_name)
            offset = original_offset
            break

        # Regular label
        start = offset + 1
        end = start + length_byte
        labels.append(packet[start:end].decode("ascii", errors="replace"))
        offset = end

    return ".".join(labels), offset


def _parse_rdata(packet: bytes, rtype: int, rdata: bytes, rdata_offset: int) -> str:
    """Interpret RDATA bytes based on record type."""
    if rtype == RECORD_TYPES["A"] and len(rdata) == 4:
        return socket.inet_ntoa(rdata)

    if rtype == RECORD_TYPES["AAAA"] and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)

    if rtype in (RECORD_TYPES["NS"], RECORD_TYPES["CNAME"], RECORD_TYPES["PTR"]):
        name, _ = _decode_name(packet, rdata_offset)
        return name

    if rtype == RECORD_TYPES["MX"]:
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = _decode_name(packet, rdata_offset + 2)
        return f"{preference} {exchange}"

    if rtype == RECORD_TYPES["TXT"]:
        # TXT RDATA is one or more length-prefixed strings
        strings = []
        pos = 0
        while pos < len(rdata):
            slen = rdata[pos]
            strings.append(rdata[pos + 1:pos + 1 + slen].decode("utf-8", errors="replace"))
            pos += 1 + slen
        return "".join(strings)

    if rtype == RECORD_TYPES["SOA"]:
        mname, next_off = _decode_name(packet, rdata_offset)
        rname, next_off2 = _decode_name(packet, next_off)
        rest = packet[next_off2:next_off2 + 20]
        if len(rest) == 20:
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", rest)
            return f"{mname} {rname} (serial={serial}, refresh={refresh}, retry={retry}, expire={expire}, min={minimum})"
        return f"{mname} {rname}"

    if rtype == RECORD_TYPES["CAA"]:
        if len(rdata) < 2:
            return rdata.hex()
        flags = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii", errors="replace")
        value = rdata[2 + tag_len:].decode("ascii", errors="replace")
        return f"{flags} {tag} \"{value}\""

    return rdata.hex()  # unknown type — show raw hex rather than fail


def query(domain: str, record_type: str, resolver: str = None, timeout: float = 5.0) -> dict:
    """
    Query a single DNS record type for `domain`.
    Returns {"success": bool, "records": [...], "error": str|None}
    """
    rtype_num = RECORD_TYPES.get(record_type.upper())
    if rtype_num is None:
        return {"success": False, "records": [], "error": f"Unsupported record type: {record_type}"}

    resolvers_to_try = [resolver] if resolver else DEFAULT_RESOLVERS
    query_id = random.randint(0, 0xFFFF)
    packet = _build_query(domain, rtype_num, query_id)

    last_error = None
    for server in resolvers_to_try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            response, _ = sock.recvfrom(4096)
            sock.close()

            result = _parse_response(response, query_id)
            result["resolver_used"] = server
            return result

        except socket.timeout:
            last_error = f"Timeout querying {server}"
            continue
        except OSError as e:
            last_error = f"Network error querying {server}: {e}"
            continue

    return {"success": False, "records": [], "error": last_error or "All resolvers failed"}


def _parse_response(packet: bytes, expected_id: int) -> dict:
    if len(packet) < 12:
        return {"success": False, "records": [], "error": "Response too short to be valid DNS"}

    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])

    if resp_id != expected_id:
        return {"success": False, "records": [], "error": "Response ID mismatch (possible spoofing or stale packet)"}

    rcode = flags & 0x000F
    RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
    if rcode != 0:
        return {"success": False, "records": [],
                "error": f"DNS server returned {RCODE_NAMES.get(rcode, f'RCODE {rcode}')}",
                "rcode": RCODE_NAMES.get(rcode, rcode)}

    offset = 12
    # Skip question section
    for _ in range(qdcount):
        _, offset = _decode_name(packet, offset)
        offset += 4  # QTYPE(2) + QCLASS(2)

    records = []
    for _ in range(ancount):
        name, offset = _decode_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        rdata_offset = offset + 10
        rdata = packet[rdata_offset:rdata_offset + rdlength]

        value = _parse_rdata(packet, rtype, rdata, rdata_offset)
        records.append({
            "name": name, "type": RECORD_TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
            "ttl": ttl, "value": value,
        })
        offset = rdata_offset + rdlength

    return {"success": True, "records": records, "error": None}


def full_lookup(domain: str, record_types: list = None, resolver: str = None) -> dict:
    """Query multiple record types for a domain in one call."""
    record_types = record_types or ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA"]
    results = {}
    for rt in record_types:
        results[rt] = query(domain, rt, resolver=resolver)
    return results


def reverse_lookup(ip: str, resolver: str = None, timeout: float = 5.0) -> dict:
    """PTR lookup: IP -> hostname. Requires encoding the IP as an in-addr.arpa name."""
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return {"success": False, "records": [], "error": "Only IPv4 reverse lookup is supported."}
        arpa_name = ".".join(reversed(octets)) + ".in-addr.arpa"
    except Exception as e:
        return {"success": False, "records": [], "error": str(e)}

    return query(arpa_name, "PTR", resolver=resolver, timeout=timeout)
