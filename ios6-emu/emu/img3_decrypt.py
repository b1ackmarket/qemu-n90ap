#!/usr/bin/env python3
"""IMG3 parser/decryptor for iOS 6 firmware components (kernelcache/iBoot/LLB/devicetree).
Usage:
  img3_decrypt.py <in.img3> <out.bin> <key64hex> <iv32hex>
After decryption the DATA payload of code images is LZSS-compressed (iOS 6 era);
devicetree DATA is plaintext IM4M-style plist-ish blob.
"""
import sys, struct
from Crypto.Cipher import AES


def parse(img3: bytes):
    if img3[:4][::-1] != b'Img3':
        raise ValueError('not IMG3: magic=%r' % img3[:4])
    full_size, data_size, sig_size = struct.unpack_from('<III', img3, 4)
    off = 0x14
    tags = {}
    data = None
    while off < min(full_size, len(img3)):
        tag_magic = img3[off:off+4][::-1]  # stored little-endian reversed
        tag_total, tag_data = struct.unpack_from('<II', img3, off+4)
        if tag_total < 12:
            break
        payload = img3[off+12:off+tag_total]
        if tag_magic == b'DATA':
            data = payload[:tag_data]
        else:
            tags[tag_magic.decode('latin1')] = payload[:tag_data]
        off += tag_total
    return tags, data


def decrypt(img3: bytes, key_hex: str, iv_hex: str) -> bytes:
    tags, data = parse(img3)
    if data is None:
        raise ValueError('no DATA tag')
    k = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.decrypt(data[:len(data) // 16 * 16]) + data[len(data) // 16 * 16:]


def lzss_decompress(src: bytes, dst_size: int = 0x800000) -> bytes:
    """Apple boot-time LZSS (same window scheme as pwnage tool / kernel 'complzss').
    Begins with magic FF E1 (uint16 flag bits big-endian)."""
    if src[:2] != b'\xff\xe1':
        raise ValueError('not lzss (magic=%r)' % src[:2])
    flags = int.from_bytes(src[:2], 'big')
    bit = 16
    src_off = 2
    dst = bytearray()
    while src_off < len(src) and len(dst) < dst_size:
        if bit == 16:
            flags = int.from_bytes(src[src_off:src_off+2], 'big')
            bit = 0
            src_off += 2
        if flags & (0x8000 >> bit):  # back-reference
            b0, b1 = src[src_off], src[src_off+1]
            src_off += 2
            length = (b0 >> 4) + 3
            disp = ((b0 & 0xF) << 8) | b1
            disp += 3
            for _ in range(length):
                dst.append(dst[-disp])
        else:  # literal
            dst.append(src[src_off])
            src_off += 1
        bit += 1
    return bytes(dst)


if __name__ == '__main__':
    in_path, out_path = sys.argv[1], sys.argv[2]
    key, iv = (sys.argv[3:5] if len(sys.argv) > 4 else (None, None))
    raw = open(in_path, 'rb').read()
    tags, data = parse(raw)
    print('tags:', {k: (len(v)) for k, v in tags.items()}, 'data:', len(data) if data else 0)
    if key:
        payload = decrypt(raw, key, iv)
    else:
        payload = data
    open(out_path, 'wb').write(payload)
    print('wrote', out_path, len(payload), 'bytes, first16=', payload[:16].hex())
