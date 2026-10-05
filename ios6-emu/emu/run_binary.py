#!/usr/bin/env python3
"""
Layer 2 —— 在 Unicorn(Qiling) 上真实执行 iOS 6 的 ARM 机器码。

用法:
  # 先用 rootfs 自带的系统命令验证执行层(不需要 IPA):
  python3 emu/run_binary.py --rootfs work/rootfs --bin work/rootfs/usr/bin/du

  # 静态分析 IPA(不执行):
  python3 emu/run_binary.py --rootfs work/rootfs --ipa app.ipa --info

  # 真实执行尝试:
  python3 emu/run_binary.py --rootfs work/rootfs --ipa app.ipa

退出码: 0=跑完  2=前置条件不满足  3=执行层死在预期的系统服务缺口
"""
import argparse
import os
import plistlib
import re
import struct
import sys
import tempfile
import zipfile

MH_FAT_LE = 0xBEBAFECA          # 'CAFEBABE' 按小端读
MH_MAGIC_32LE, MH_MAGIC_32BE = 0xFEEDFACE, 0xCEFAEDFE
MH_MAGIC_64LE, MH_MAGIC_64BE = 0xFEEDFACF, 0xCFFAEDFE
CPU_ARM, CPU_ARM64 = 12, 0x0100000C

FT_NAMES = {2: '可执行程序', 6: '动态库', 8: 'bundle', 12: 'kext'}


def rd(fmt, data, off, le):
    return struct.unpack_from(('<' if le else '>') + fmt, data, off)


def macho_summary(data, depth=0):
    """解析 Mach-O(fat/thin,大小端),返回摘要 dict 或 None。"""
    if len(data) < 32 or depth > 2:
        return None
    magic = rd('I', data, 0, True)[0]
    if magic == MH_FAT_LE:  # FAT
        n = rd('I', data, 4, False)[0]
        for i in range(min(n, 8)):
            cputype = rd('I', data, 8 + i * 20, False)[0]
            offset = rd('I', data, 8 + i * 20 + 8, False)[0]
            if cputype in (CPU_ARM, CPU_ARM64):
                sub = macho_summary(data[offset:], depth + 1)
                if sub:
                    sub['fat'] = f'从 FAT 中选取 (offset {offset:#x})'
                return sub
        return {'arch': 'FAT(无 ARM 切片)'}
    if magic == MH_MAGIC_32LE:
        le, is64 = True, False
    elif magic == MH_MAGIC_32BE:
        le, is64 = False, False
    elif magic == MH_MAGIC_64LE:
        le, is64 = True, True
    elif magic == MH_MAGIC_64BE:
        le, is64 = False, True
    else:
        return None
    cputype, cpusub, ftype, ncmds, sizeofcmds, flags = rd('6I', data, 4, le)
    info = {
        'arch': ('ARM64' if cputype == CPU_ARM64 else 'ARM 32位') + f' (cputype {cputype:#x}, subtype {cpusub})',
        'is64': is64, 'le': le, 'cputype': cputype,
        'filetype': FT_NAMES.get(ftype, f'type {ftype}'),
        'minos': None, 'cryptid': None, 'dylibs': [], 'uuid': None, 'install': None,
    }
    q = 32 if is64 else 28
    for _ in range(min(ncmds, 512)):
        if q + 8 > len(data):
            break
        cmd, size = rd('II', data, q, le)
        if size < 8:
            break
        try:
            if cmd == 0x25 and size >= 16:                     # LC_VERSION_MIN_IPHONEOS
                v = rd('I', data, q + 8, le)[0]
                info['minos'] = f'{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}'
            elif cmd == 0x2C and size >= 20:                   # LC_ENCRYPTION_INFO (32位)
                info['cryptid'] = rd('I', data, q + 16, le)[0]
            elif cmd == 0x1B and size >= 24:                   # LC_UUID
                info['uuid'] = data[q + 8:q + 24].hex()
            elif cmd == 0xD:                                   # LC_ID_DYLIB(本文件自己的安装名)
                noff = rd('I', data, q + 8, le)[0]
                end = data.find(b'\x00', q + noff)
                info['install'] = data[q + noff:end if end > 0 else q + size].decode('ascii', 'replace')
            elif cmd == 0xC:                                   # LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
                noff = rd('I', data, q + 8, le)[0]
                end = data.find(b'\x00', q + noff)
                name = data[q + noff:end if end > 0 else q + size].decode('ascii', 'replace')
                info['dylibs'].append(name)
        except Exception:
            pass
        q += size
    return info


def print_summary(s, info_plist=None):
    print('---- Mach-O 分析 ----')
    print('  架构      :', s.get('arch'), ' ', s.get('fat', ''))
    print('  类型      :', s.get('filetype'))
    if s.get('uuid'):
        print('  UUID      :', s.get('uuid'))
    if s.get('minos'):
        print('  最低系统  : iOS', s.get('minos'))
    if s.get('minos') and tuple(int(x) for x in s['minos'].split('.')[:2]) > (6, 99):
        print('  ⚠️ 该二进制要求的 iOS 版本高于 6.x,在 iOS 6 rootfs 下注定缺依赖')
    c = s.get('cryptid')
    if c == 1:
        print('  FairPlay  : ✗ 已加密 (cryptid=1)')
    elif c == 0:
        print('  FairPlay  : ✓ 未加密,可被真实模拟器加载')
    if info_plist:
        for k in ('CFBundleDisplayName', 'CFBundleIdentifier', 'CFBundleShortVersionString', 'MinimumOSVersion'):
            if info_plist.get(k):
                print(f'  {k}: {info_plist[k]}')
    dy = s.get('dylibs') or []
    print(f'  链接 {len(dy)} 个动态库:')
    for d in dy[:20]:
        print('    ', d.split('/')[-1])
    if len(dy) > 20:
        print(f'    … 共 {len(dy)} 个')


def load_ipa(ipa_path, outdir):
    with zipfile.ZipFile(ipa_path) as z:
        names = [n for n in z.namelist() if not n.endswith('/')]
        pls = [n for n in names if re.match(r'^Payload/[^/]+\.app/Info\.plist$', n, re.I)]
        if not pls:
            raise SystemExit('错误: IPA 中没有 Payload/*.app/Info.plist')
        info = plistlib.loads(z.read(pls[0]))
        appdir = os.path.dirname(pls[0])
        exe = info.get('CFBundleExecutable') or \
              os.path.basename(appdir)[:-4] or info.get('CFBundleName')
        binn = f'{appdir}/{exe}'
        if binn not in names:
            raise SystemExit(f'错误: IPA 中找不到主二进制 {binn}')
        target = os.path.join(outdir, 'payload_bin')
        with z.open(binn) as src, open(target, 'wb') as dst:
            dst.write(src.read())
        return target, info


def thin_arm(binary_path):
    """FAT 二进制 → 抽出 ARM 切片(Qiling 只吃 thin)。"""
    data = open(binary_path, 'rb').read()
    magic = rd('I', data, 0, True)[0]
    if magic != MH_FAT_LE:
        return binary_path
    n = rd('I', data, 4, False)[0]
    for i in range(min(n, 8)):
        cputype = rd('I', data, 8 + i * 20, False)[0]
        offset, size = rd('II', data, 8 + i * 20 + 8, False)
        if cputype == CPU_ARM:
            out = binary_path + '.armv7'
            with open(out, 'wb') as f:
                f.write(data[offset:offset + size])
            print(f'== FAT 检测到,已抽出 ARM 切片 → {out} ({size} bytes)')
            return out
    raise SystemExit('错误: FAT 中没有 ARM 切片(此模拟器只支持 32 位 iOS 6 应用)')


def diagnose(exc):
    text = f'{type(exc).__name__}: {exc}'
    rules = [
        ('dyld_shared_cache', '依赖的框架在 dyld 共享缓存里、磁盘上没有 → 先运行 scripts/04_dsc.sh 提取缓存中的框架'),
        ('dylib', '动态库缺失 → 确认 work/rootfs 完整;弱链接缺失可忽略'),
        ('bootstrap', 'Mach bootstrap 服务缺失:没有 launchd/WindowServer —— 这是 GUI 应用当前阶段的预期死点'),
        ('mach_msg', 'Mach IPC 未仿真:窗口服务器/IOKit 不存在 —— GUI 应用当前阶段的预期死点'),
        ('IOKit', 'IOKit 未仿真:需要内核驱动服务(GUI/硬件访问的预期死点)'),
        ('UcError', 'CPU 访问了未映射内存:通常是调用未仿真的系统调用或缺失服务后跑飞'),
    ]
    for key, msg in rules:
        if key.lower() in text.lower():
            return f'死因判定 → {msg}\n原始错误: {text}'
    return f'死因未分类。原始错误: {text}'


def run_qiling(binpath, rootfs, arch, debug, timeout):
    try:
        from qiling import Qiling
    except ImportError:
        raise SystemExit('未安装 qiling,先运行 ./setup.sh(pip install qiling unicorn capstone)')

    kwargs = {}
    if debug:
        try:
            from qiling.log import QL_VERBOSE
            kwargs['verbose'] = QL_VERBOSE.DEBUG
        except Exception:
            kwargs['verbose'] = 15
    print(f'== Qiling 启动: {binpath}')
    print(f'   sysroot = {rootfs}  arch = {arch}')
    ql = Qiling([binpath], rootfs, ostype='ios', arch=arch, **kwargs)
    import signal

    def on_alarm(sig, frame):
        try:
            pc = ql.arch.regs.pc if hasattr(ql, 'arch') else '?'
        except Exception:
            pc = '?'
        print(f'\n== 超时({timeout}s)未退出,最后 PC = {pc}')
        os._exit(3)

    if timeout:
        signal.signal(signal.SIGALRM, on_alarm)
        signal.alarm(timeout)
    try:
        ql.run()
        print('== 执行结束(exit 未崩溃)')
    except KeyboardInterrupt:
        print('== 手动中断')
    except Exception as e:  # noqa: BLE001
        print(diagnose(e))
        sys.exit(3)
    finally:
        if timeout:
            signal.alarm(0)


def main():
    ap = argparse.ArgumentParser(description='iOS 6 ARM 代码真实执行器(Qiling/Unicorn)')
    ap.add_argument('--rootfs', default=os.path.join(os.path.dirname(__file__), '..', 'work', 'rootfs'))
    ap.add_argument('--ipa')
    ap.add_argument('--bin')
    ap.add_argument('--info', action='store_true', help='只做静态分析,不执行')
    ap.add_argument('--trace', action='store_true', help='Qiling DEBUG 级日志')
    ap.add_argument('--timeout', type=int, default=60, help='执行超时秒数(0=不限)')
    args = ap.parse_args()

    rootfs = os.path.abspath(args.rootfs)
    tmp = None
    if args.ipa:
        tmp = tempfile.mkdtemp(prefix='ipa_')
        binpath, plist = load_ipa(args.ipa, tmp)
        summary = macho_summary(open(binpath, 'rb').read())
        if not summary:
            raise SystemExit('错误: 主二进制不是可识别的 Mach-O')
        print_summary(summary, plist)
        if args.info:
            return
        if summary.get('cryptid') == 1:
            raise SystemExit('拒绝执行: 该 IPA 带 FairPlay 加密(cryptid=1)。\n'
                             '真实模拟器只能加载解密后的副本(来自越狱设备的砸壳 dump),'
                             'App Store 加密包无法直接跑。')
        binpath = thin_arm(binpath)
        arch = 'arm64' if summary.get('cputype') == CPU_ARM64 else 'arm'
    elif args.bin:
        binpath = args.bin
        summary = macho_summary(open(binpath, 'rb').read())
        if summary:
            print_summary(summary)
            if args.info:
                return
        arch = 'arm64' if summary and summary.get('cputype') == CPU_ARM64 else 'arm'
    else:
        ap.error('需要 --ipa 或 --bin')

    if not os.path.isdir(os.path.join(rootfs, 'System')):
        raise SystemExit(f'错误: {rootfs} 不是 iOS rootfs(缺 System/)。先跑 scripts/01~03。')

    run_qiling(binpath, rootfs, arch,
               debug=args.trace,
               timeout=args.timeout)


if __name__ == '__main__':
    main()
