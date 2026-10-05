#!/usr/bin/env python3
"""
解密 iOS FileVault-V2("encrcdsa")加密的 rootfs DMG —— iPad2/iOS 4~6 时代的格式。

结构(参考 xpwn dmg/filevault.c 与 includes/dmg/filevault.h):
  文件头(明文, big-endian): signature 'encrcdsa' + blockSize/dataSize/dataOffset 等
  数据区: 从 dataOffset 起,按 blockSize 分块,AES-128-CBC 独立加密
  每块的 IV = HMAC-SHA1(hmacKey, chunkNo_bigend32)[:16]

密钥串(-k)格式: 32 hex(AES key) + 40 hex(HMAC-SHA1 key) = 72 hex
(theiphonewiki 的 rootfs "key" 字段即整个 72 hex)

用法: dmg_decrypt.py <in.dmg> <out.dmg> <key72hex>
"""
import hmac
import hashlib
import os
import struct
import sys

from Crypto.Cipher import AES


def parse_header(raw):
    sig, = struct.unpack_from('>Q', raw, 0)
    if sig != 0x656e637263647361:
        raise SystemExit(f'魔数不符: {sig:#x}(期望 encrcdsa)——文件可能已解密或不是该格式')
    version, enc_iv_size = struct.unpack_from('>II', raw, 8)
    block_size, = struct.unpack_from('>I', raw, 52)
    data_size, data_offset = struct.unpack_from('>QQ', raw, 56)
    return version, block_size, data_size, data_offset


def decrypt(in_path, out_path, key_hex):
    key_hex = key_hex.strip().lower()
    if len(key_hex) != 72:
        raise SystemExit(f'key 需要 72 hex(AES 32 + HMAC 40),收到 {len(key_hex)}')
    aes_key = bytes.fromhex(key_hex[:32])
    hmac_key = bytes.fromhex(key_hex[32:])
    assert len(aes_key) == 16 and len(hmac_key) == 20

    with open(in_path, 'rb') as f:
        version, block_size, data_size, data_offset = parse_header(f.read(72))
    print(f'== FileVault V2: version={version} blockSize={block_size} '
          f'dataSize={data_size // 1024 // 1024}MB dataOffset={data_offset}')

    n_chunks = (data_size + block_size - 1) // block_size
    done = 0
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for chunk_no in range(n_chunks):
            fin.seek(chunk_no * block_size + data_offset)
            ct = fin.read(block_size)
            iv = hmac.new(hmac_key, struct.pack('>I', chunk_no), hashlib.sha1).digest()[:16]
            pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct)
            fout.write(pt)
            done += block_size
            if chunk_no % 8192 == 0:
                pct = min(100, done * 100 // data_size)
                print(f'   {pct}%  (chunk {chunk_no}/{n_chunks})', end='\r')
    print(f'\n== 解密完成: {out_path} ({data_size // 1024 // 1024}MB 明文数据)')


def verify(path):
    """校验:UDIF koly 尾魔数(明文是带 zlib 分块的 UDIF,H+ 卷头在分块内看不到)"""
    ok = True
    with open(path, 'rb') as f:
        f.seek(-512, 2)
        tail = f.read(4)
        print('   koly 尾魔数:', tail, "(期望 b'koly')")
        ok &= tail == b'koly'
    print('   (明文为 UDIF 结构,直接 hdiutil attach 即可挂载)')
    return ok


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--verify':
        sys.exit(0 if verify(sys.argv[2]) else 1)
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    decrypt(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(0 if verify(sys.argv[2]) else 1)
