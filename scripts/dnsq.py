#!/usr/bin/env python3
"""Minimal DNS query client for manual checks.

No third-party modules: builds a UDP query by hand and prints the answer
records in a readable form.

    python3 scripts/dnsq.py xvideos.com A --port 5354
    python3 scripts/dnsq.py example.com AAAA --server 192.168.1.20 --port 53
"""
import argparse
import random
import socket
import struct
import sys

TYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
        "TXT": 16, "AAAA": 28, "SRV": 33, "SVCB": 64, "HTTPS": 65}


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError("label too long: " + label)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, qtype):
    qid = random.randrange(0, 65536)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return qid, header + encode_name(name) + struct.pack("!HH", TYPE[qtype], 1)


def read_name(msg, offset):
    labels = []
    while True:
        length = msg[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", msg[offset:offset + 2])[0] & 0x3FFF
            name, _ = read_name(msg, pointer)
            labels.append(name)
            return ".".join(labels), offset + 2
        labels.append(msg[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("qtype", nargs="?", default="A", choices=sorted(TYPE))
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5354)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    qid, packet = build_query(args.name, args.qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sock.sendto(packet, (args.server, args.port))
    try:
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        print("TIMEOUT after %.1fs" % args.timeout)
        return 1

    rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    print("id=%d rcode=%d answers=%d authority=%d additional=%d" % (rid, rcode, an, ns, ar))
    offset = 12
    for _ in range(qd):
        name, offset = read_name(data, offset)
        offset += 4
        print("question: %s" % name)
    for _ in range(an):
        name, offset = read_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            value = ".".join(str(b) for b in rdata)
        elif rtype == 28 and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        else:
            value = rdata.hex()
        print("answer: %s type=%d ttl=%d %s" % (name, rtype, ttl, value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
