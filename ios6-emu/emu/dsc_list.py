#!/usr/bin/env python3
"""
dyld 共享缓存(iOS 6 时代为 dyld_v1 armv7 格式)工具。

子命令:
  list <cache>                        列出缓存里的镜像(诊断用,纯 Python 解析)
  install --dsc-dir DIR --rootfs DIR  把提取出的 dylib 按 install name 摆进 rootfs
                                      (Qiling 解析 /System/Library/... 依赖时会用到)

iOS 6 的 UIKit/Foundation 等主流框架不是磁盘上的独立文件,而是打包在
/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7 里。
想让 GUI 类 IPA 的依赖能被解析,必须先解出缓存。
"""
import argparse
import os
import struct
import sys

from run_binary import macho_summary  # 复用 Mach-O 解析


def list_cache(path):
    fsize = os.path.getsize(path)
    f = open(path, 'rb')
    head = f.read(64 * 1024)  # 头部 + 完整条目表
    magic = head[:16].split(b'\x00')[0].decode('ascii', 'replace')
    if not magic.startswith('dyld_v1'):
        print(f'不认识的缓存格式: {magic!r}(本工具针对 dyld_v1 armv7)——列表仍可尝试')
    mappingOffset, mappingCount, imagesOffset, imagesCount = struct.unpack_from('<4I', head, 16)
    print(f'格式: {magic}  映射段: {mappingCount}  镜像数: {imagesCount}')

    def read_path(pathoff):
        if pathoff >= fsize or pathoff < 16:
            return None
        f.seek(pathoff)
        raw = f.read(512)
        end = raw.find(b'\x00')
        try:
            return raw[:end if end > 0 else 512].decode('ascii')
        except UnicodeDecodeError:
            return None

    # 条目布局跨版本不同:自动探测 (stride, pathOffset 字段位置)
    # 注意:路径字符串可能散布在整个文件中(各镜像数据附近),不能只用头部窗口判断
    best = None
    for stride, poff in ((32, 24), (28, 24), (16, 12), (24, 16)):
        if imagesOffset + imagesCount * stride > fsize:
            continue
        ok = 0
        n = min(imagesCount, 80)
        for i in range(n):
            pathoff = struct.unpack_from('<I', head, imagesOffset + i * stride + poff)[0]
            if read_path(pathoff) and (
                read_path(pathoff).startswith('/System/') or read_path(pathoff).startswith('/usr/')):
                ok += 1
        if n and ok / n > 0.8:
            best = (stride, poff)
            break
    if not best:
        print('未能确定镜像表结构:缓存可能不是 v1 格式,改用 scripts/04_dsc.sh 的 ipsw 路径。')
        return 1
    stride, poff = best
    print(f'条目结构: stride={stride}, pathOffset 字段在 +{poff}')
    paths = []
    for i in range(imagesCount):
        pathoff = struct.unpack_from('<I', head, imagesOffset + i * stride + poff)[0]
        p = read_path(pathoff)
        if p:
            paths.append(p)
    fw = sorted(set(p.split('/')[3] for p in paths if p.startswith('/System/Library/') and len(p.split('/')) > 4))
    print(f'可读路径 {len(paths)} 个;System/Library 下顶层目录:')
    for x in fw[:20]:
        print('   ', x)
    return 0


def cmd_install(dsc_dir, rootfs):
    """把提取出的 dylib 复制到 rootfs 中其 install name 指定的路径。"""
    import shutil
    n_ok = n_skip = 0
    for dirpath, _, files in os.walk(dsc_dir):
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                with open(p, 'rb') as f:
                    s = macho_summary(f.read())
            except OSError:
                continue
            if not s or not s.get('install') or not s['install'].startswith('/'):
                n_skip += 1
                continue
            dst = os.path.join(rootfs, s['install'].lstrip('/'))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst):
                shutil.copyfile(p, dst)
                n_ok += 1
    print(f'按 install name 部署完成: 新增 {n_ok} 个,跳过 {n_skip} 个')
    print('现在 Qiling 解析 /System/Library/Frameworks/... 依赖时可以找到缓存中的框架了。')
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p1 = sub.add_parser('list')
    p1.add_argument('cache')
    p2 = sub.add_parser('install')
    p2.add_argument('--dsc-dir', required=True)
    p2.add_argument('--rootfs', required=True)
    a = ap.parse_args()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    if a.cmd == 'list':
        sys.exit(list_cache(a.cache))
    else:
        sys.exit(cmd_install(a.dsc_dir, a.rootfs))


if __name__ == '__main__':
    main()
