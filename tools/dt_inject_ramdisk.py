#!/usr/bin/env python3
"""
dt_inject_ramdisk.py — inject a RAMDisk property into the iPhone boot
device tree, so xnu-1735's IOFindBSDRoot() finds it via
'/chosen/memory-map' and registers an md0 memory device (rd=md0).

Flat device tree format (Apple's "flattened" binary layout the kernel's
IODeviceTree consumes):
    node    ::= u32 nprops, u32 nchildren, prop*, child*
    prop    ::= CHAR name[NUL], u32 length, BYTE value[length],
                pad to 4-byte boundary
The RAMDisk prop value is 8 bytes: { u32 phys_base, u32 size_in_bytes }.

Kernel side (IOKitBSDInit.cpp):
    RAMDParms = data->getBytesNoCopy();
    mdevadd(-1, ml_static_ptovirt(ramdParms[0]) >> 12, ramdParms[1] >> 12, 0);
So the base we store is the PHYSICAL address the ramdisk image was bundled
at; ml_static_ptovirt maps it back into the kernel window (va = pa +
0x40000000) and mdevadd stores PAGE numbers.

Usage:
    python3 dt_inject_ramdisk.py devicetree.dec 0x50000000 20148256 out.bin
"""

import struct
import sys


def al4(n):
    return (n + 3) & ~3


def encode_prop(name, val):
    name_b = name.encode() + b"\0"
    assert len(name_b) <= 32
    b = name_b.ljust(32, b"\0") + struct.pack("<I", len(val)) + val
    return b + b"\0" * (al4(len(b)) - len(b))


class Node:
    __slots__ = ("start", "end", "nprops", "nchildren", "props", "children")

    def __init__(self, start, end, nprops, nchildren):
        self.start, self.end = start, end
        self.nprops, self.nchildren = nprops, nchildren
        self.props = []      # (name, value_bytes, raw_bytes)
        self.children = []

    def find(self, path):
        node = self
        for name in path:
            nxt = None
            for c in node.children:
                for cname, cval, _ in c.props:
                    if cname == "name" and cval.split(b"\0")[0].decode("utf-8", "replace") == name:
                        nxt = c
                        break
                if nxt is not None:
                    break
            if nxt is None:
                return None
            node = nxt
        return node

    def build(self):
        body = struct.pack("<II", self.nprops, self.nchildren)
        for name, val, raw in self.props:
            body += raw if raw is not None else encode_prop(name, val)
        for ch in self.children:
            body += ch.build()
        return body


def parse(buf, off):
    nprops, nchildren = struct.unpack_from("<II", buf, off)
    start = off
    off += 8
    props = []
    for _ in range(nprops):
        pstart = off
        name = buf[off:off + 32].split(b"\0")[0].decode("utf-8", "replace")
        off += 32
        length = struct.unpack_from("<I", buf, off)[0]
        off += 4
        val = buf[off:off + length]
        off += length
        off = al4(off)
        props.append((name, val, pstart))
    node = Node(start, off, nprops, nchildren)
    node.props = props
    for _ in range(nchildren):
        child, off = parse(buf, off)
        node.children.append(child)
    return node, off


def main():
    import sys
    # argv: src base_hex size out
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(1)
    src, base_s, size_s, dst = sys.argv[1:5]
    base = int(base_s, 0)
    size = int(size_s, 0)

    buf = open(src, "rb").read()
    root, end = parse(buf, 0)
    print(f"root: {root.nprops} props, {root.nchildren} children, "
          f"parsed {end} bytes of {len(buf)}")

    mm = root.find(["chosen", "memory-map"])
    if mm is None:
        sys.exit("E: /chosen/memory node not found. Available children: " +
                 ", ".join(c.props[0][0] for c in root.children))
    print(f"memory-map node at byte {mm.start}-{mm.end}, "
          f"{mm.nprops} props, {mm.nchildren} children")

    new_prop = encode_prop("RAMDisk", struct.pack("<II", base, size))
    print(f"RAMDisk prop = {{0x{base:08x}, {size}}} = "
          f"{new_prop.hex()} ({len(new_prop)} bytes)")

    # splice: rewrite the memory-map node body with the extra prop, then
    # the remainder of the tree.
    body = struct.pack("<II", mm.nprops + 1, mm.nchildren)
    body += new_prop
    for name, val, raw in mm.props:
        body += encode_prop(name, val)
    # children follow after node end in the original buffer; keep them raw
    tail = buf[mm.end:]

    out = buf[:mm.start] + body + tail
    # sanity re-parse
    root2, end2 = parse(out, 0)
    mm2 = root2.find(["chosen", "memory-map"])
    if mm2 is None:
        print("ERROR: injected tree doesn't re-parse!")
        sys.exit(1)
    names = [n for n, _, _ in mm2.props]
    print(f"verified: memory-map now {mm2.nprops} props, "
          f"RAMDisk present = {'RAMDisk' in names}")
    with open(dst, "wb") as f:
        f.write(out)
    print(f"wrote {dst} ({len(out)} bytes, was {len(buf)})")


if __name__ == "__main__":
    main()