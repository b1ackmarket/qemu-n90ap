#!/usr/bin/env python3
"""
Layer 2 核心 —— 最小 XNU 用户态层:用 Unicorn(真 ARMv7 CPU 仿真)启动 iOS 6 真实的 dyld,
由 dyld 自己完成:解析主程序 → mmap dyld 共享缓存 → 绑定符号 → 跳到程序入口。

我们只仿真内核暴露给用户态的最小面(SVC 系统调用/Mach 陷阱),其余全部是真 iOS 机器码在工作。

栈约定来自 dyld-210.2.3/src/dyldStartup.s (_dyld_start):
    [sp+0] = 主程序 mach_header 地址
    [sp+4] = argc
    [sp+8] = argv[](NULL 结尾),其后 envp[]、apple[](各 NULL 结尾)

用法:
  .venv/bin/python3 emu/xnu_boot.py --bin work/rootfs/sbin/launchd
  .venv/bin/python3 emu/xnu_boot.py --bin work/rootfs/sbin/mount --trace-syscalls
"""
import argparse
import os
import struct
import sys

from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_MEM_INVALID,
                     UC_HOOK_CODE)
from collections import deque
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
    UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R12, UC_ARM_REG_SP,
    UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_CPSR,
    UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC, UC_ARM_REG_C13_C0_3,
)

PAGE = 0x1000
STACK_TOP = 0x40000000
STACK_SIZE = 8 * 1024 * 1024
MMAP_BASE = 0x50000000
MMAP_LIMIT = 0x70000000
TSD_BASE = 0x60000000          # 主线程 TLS(TPIDRURW);libc 的 __error/TSD 直接读它
PTHREAD_FAKE = 0x60000100
PTHREAD_MAGIC = 0x54485444     # dyld _pthread_getspecific_direct 校验值(实测)

ERRNO_ENOENT = 2
ERRNO_EBADF = 9
ERRNO_ENOMEM = 12
ERRNO_ENOTSUP = 45


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


class XNUUserland:
    def __init__(self, rootfs, trace=False, max_instr=None, code_trace=None):
        self.rootfs = os.path.abspath(rootfs)
        self.trace = trace
        self.max_instr = max_instr
        self.code_trace = open(code_trace, 'w') if code_trace else None
        self.instr_seen = 0
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        # 启用 VFP/NEON 协处理器(Unicorn ARM 默认关闭,否则 vst1 等指令报 INVALID)
        self.uc.reg_write(UC_ARM_REG_C1_C0_2, self.uc.reg_read(UC_ARM_REG_C1_C0_2) | 0xF00000)
        self.uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        self.open_files = {}          # fd -> [host_path, file_obj, size, pos]
        self.next_fd = 3
        self.mmap_next = MMAP_BASE
        self.instr_count = 0
        self.syscall_count = {}
        self.svc_history = []         # 最近 SVC 记录(调试死点用)
        self.ins_hist = deque(maxlen=64)  # 最近 64 条指令(停止时 dump)
        self.mapped = []              # (start, end) 页区间
        self.stopped = None
        self.uc.hook_add(UC_HOOK_INTR, self.hook_intr)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE)
        self.mapped.append((STACK_TOP - STACK_SIZE, STACK_TOP))
        # armv7 iOS commpage(内核共享页,libc/dyld 会读它的例程表)——零页=无优化例程,走 libc 回退
        self.uc.mem_map(0xFFFF0000, 0x2000)
        self.mapped.append((0xFFFF0000, 0xFFFF2000))
        # 主线程 TLS 基址(真内核在 exec 时设置;dyld 的 __error/errno 依赖它)
        self.uc.mem_map(TSD_BASE, PAGE)
        self.mapped.append((TSD_BASE, TSD_BASE + PAGE))
        self.uc.mem_write(PTHREAD_FAKE, struct.pack('<I', PTHREAD_MAGIC))
        self.uc.mem_write(TSD_BASE, struct.pack('<I', PTHREAD_FAKE))  # TSD[0] = pthread self
        self.uc.reg_write(UC_ARM_REG_C13_C0_3, TSD_BASE)

    # ---------- 基础 ----------
    def hook_code(self, uc, address, size, user_data):
        self.instr_seen += 1
        lr = uc.reg_read(UC_ARM_REG_LR)
        self.ins_hist.append((address, lr, uc.reg_read(UC_ARM_REG_SP)))
        if self.code_trace:
            self.code_trace.write(f'{address:#x} lr={lr:#x} sp={uc.reg_read(UC_ARM_REG_SP):#x}\n')
        if address == 0x2fe012d4 and not getattr(self, '_loopdump', False):
            self._loopdump = True
            sp = uc.reg_read(UC_ARM_REG_SP)
            ncmds = struct.unpack('<I', uc.mem_read(sp + 0x10, 4))[0]
            mh = uc.reg_read(UC_ARM_REG_R4)
            print(f'\n== [探针] 加载命令循环: r4={mh:#x} ncmds@sp+0x10={ncmds:#x}')
            try:
                hdr = bytes(uc.mem_read(mh, 0x20))
                print(f'   [r4] 前32字节: {hdr.hex()} (magic={hdr[:4].hex()})')
            except Exception as e:
                print(f'   [r4] 不可读: {e}')
            try:
                hdr2 = bytes(uc.mem_read(0x1000, 0x20))
                print(f'   [launchd mh@0x1000] ncmds={struct.unpack_from("<I", hdr2, 0x10)[0]}')
            except Exception:
                pass
        if address == 0x2fe012d4:
            self._loop_hits = getattr(self, '_loop_hits', 0) + 1
            if self._loop_hits <= 20 or self._loop_hits % 500 == 0:
                sp = uc.reg_read(UC_ARM_REG_SP)
                ncmds = struct.unpack('<I', uc.mem_read(sp + 0x10, 4))[0]
                i = struct.unpack('<I', uc.mem_read(sp + 0x14, 4))[0]
                cmd = uc.reg_read(UC_ARM_REG_R0)
                print(f'   [循环 #{self._loop_hits}] i={i} ncmds={ncmds:#x} cmd@r0={cmd:#x}')

    def log(self, *a):
        if self.trace:
            print(*a)

    def is_mapped(self, start, end):
        for s, e in self.mapped:
            if start < e and end > s:
                return True
        return False

    def map_range(self, start, size):
        start &= ~0xFFF
        end = align_up(start + size)
        for page in range(start, end, PAGE):
            if not self.is_mapped(page, page + PAGE):
                self.uc.mem_map(page, PAGE)
        if not self.is_mapped(start, end):
            self.mapped.append((start, end))
        else:
            self.mapped.append((start, end))

    def write_mem(self, addr, data):
        self.map_range(addr, len(data))
        self.uc.mem_write(addr, data)

    def read_cstr(self, addr, maxlen=1024):
        out = b''
        while len(out) < maxlen:
            b = self.uc.mem_read(addr + len(out), 1)
            if b == b'\x00':
                break
            out += bytes(b)
        return out.decode('utf-8', 'replace')

    # ---------- Mach-O ----------
    def load_macho(self, path):
        """按 LC_SEGMENT 映射到声明地址,返回 (entry, header_addr, slide)"""
        data = open(path, 'rb').read()
        magic, = struct.unpack_from('<I', data, 0)
        if magic == 0xBEBAFECA:  # FAT: 取 ARM 切片
            n, = struct.unpack_from('>I', data, 4)
            off = None
            for i in range(n):
                ct, = struct.unpack_from('>I', data, 8 + i * 20)
                if ct == 12:
                    off, size = struct.unpack_from('>II', data, 8 + i * 20 + 8)
                    data = data[off:off + size]
                    break
            assert off is not None, 'FAT 中无 ARM 切片'
            magic, = struct.unpack_from('<I', data, 0)
        le = magic in (0xFEEDFACE, 0xFEEDFACF)
        is64 = magic == 0xFEEDFACF
        fmt = '<' if le else '>'
        cputype, cpusub, ftype, ncmds, sizeofcmds, flags = struct.unpack_from(fmt + '6I', data, 4)
        q = 32 if is64 else 28
        entry = 0
        thumb = False
        segs = []
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from(fmt + 'II', data, q)
            if cmd == 0x1:  # LC_SEGMENT
                name = data[q + 8:q + 24].split(b'\x00')[0].decode()
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = \
                    struct.unpack_from(fmt + 'IIIIIIII', data, q + 24)
                segs.append((name, vmaddr, vmsize, fileoff, filesize, initprot))
            elif cmd == 0x5:  # LC_UNIXTHREAD
                p = q + 8
                while p < q + cmdsize:
                    flavor, cnt = struct.unpack_from(fmt + 'II', data, p)
                    if flavor == 1:  # ARM_THREAD_STATE
                        r = struct.unpack_from(fmt + '16I', data, p + 8)
                        entry = r[15]
                        thumb = entry & 1
                    p += 8 + cnt * 4
            q += cmdsize
        print(f'== 映射 {os.path.basename(path)}: {len(segs)} 段, entry={entry:#x} (thumb={thumb})')
        for name, vmaddr, vmsize, fileoff, filesize, initprot in segs:
            if vmsize == 0:
                continue
            self.map_range(vmaddr, vmsize)
            self.uc.mem_write(vmaddr, data[fileoff:fileoff + filesize])
            self.log(f'   {name:16s} @{vmaddr:#010x} size={vmsize:#x}')
        header_addr = next(s[1] for s in segs if s[0] == '__TEXT')
        return entry, header_addr, 0  # 固定地址加载 → slide=0

    # ---------- 启动栈 ----------
    def build_stack(self, main_mh, argv, envp, apple):
        sp = STACK_TOP - 0x1000
        def push_str(s):
            nonlocal sp
            sp -= len(s) + 1
            self.write_mem(sp, s.encode() + b'\x00')
            return sp
        argv_ptrs = []
        for a in argv:
            argv_ptrs.append(push_str(a))
        env_ptrs = [push_str(e) for e in envp]
        app_ptrs = [push_str(a) for a in apple]

        # XNU exec 行为:把主程序的 mach header + 全部 load commands 压一份副本到栈上,
        # dyldbootstrap::start 遍历的就是这份副本(dyld-210.2.3 dyldStartup.s [sp+0] 契约)
        sizeofcmds = struct.unpack('<I', self.uc.mem_read(main_mh + 0x14, 4))[0]
        copy_size = 0x20 + sizeofcmds
        sp = (sp - copy_size) & ~0xF
        hdr_copy = bytes(self.uc.mem_read(main_mh, copy_size))
        self.write_mem(sp, hdr_copy)
        main_mh = sp  # [sp+0] 指向这份副本

        sp &= ~0xF
        vec = []
        vec.append(main_mh)          # [sp+0] mach_header(栈上副本)
        vec.append(len(argv))        # [sp+4] argc
        vec += argv_ptrs + [0]
        vec += env_ptrs + [0]
        vec += app_ptrs + [0]
        body = struct.pack('<%dI' % len(vec), *vec)
        sp -= len(body)
        sp &= ~0xF
        self.write_mem(sp, body)
        return sp

    # ---------- SVC 系统调用 ----------
    def hook_intr(self, uc, intno, user_data):
        if intno != 2:  # ARM SVC
            return
        self.instr_count += 1
        num = uc.reg_read(UC_ARM_REG_R12)
        num = num - (1 << 32) if num >= 0x80000000 else num
        self.syscall_count[num] = self.syscall_count.get(num, 0) + 1
        pc = uc.reg_read(UC_ARM_REG_PC)
        self.svc_history.append((pc, num, [uc.reg_read(r) for r in
                                           (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]))
        self.svc_history[:] = self.svc_history[-24:]
        a = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                      UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5)]
        try:
            ret, err = (num < 0 and self.mach_trap(num, a)) or self.bsd_syscall(num, a)
        except Exception as e:  # noqa: BLE001
            print(f'!! 系统调用 {num} 处理异常: {e!r}')
            ret, err = 0, 0
        uc.reg_write(UC_ARM_REG_R0, ret & 0xFFFFFFFF)
        # XNU 约定:出错置 C 标志(PSR bit29),errno 在 r0
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_CPSR, (cpsr | 0x20000000) if err else (cpsr & ~0x20000000))
        # 注意:Unicorn 触发 INTR 钩子时 PC 已越过 SVC 指令,这里不要再推进

    def ret_err(self, errno):
        return errno, 1

    def bsd_syscall(self, num, a):
        r0, r1, r2 = a[0], a[1], a[2]
        if num == 1:      # exit
            self.stopped = f'exit(status={r0})'
            return 0, 0
        if num == 4:      # write
            data = bytes(self.uc.mem_read(r1, r2))
            if r0 in (1, 2):
                sys.stderr.buffer.write(data)
                sys.stderr.flush()
            return r2, 0
        if num == 5:      # open
            path = self.read_cstr(r0)
            if path in ('/dev/random', '/dev/urandom'):
                fd = self.next_fd
                self.next_fd += 1
                self.open_files[fd] = ['<random>', None, 1 << 30, 0]
                self.log(f'   open({path!r}) → fd{fd} (虚拟随机源)')
                return fd, 0
            host = os.path.join(self.rootfs, path.lstrip('/'))
            if not os.path.exists(host):
                self.log(f'   open({path!r}) → ENOENT')
                return self.ret_err(ERRNO_ENOENT)
            f = open(host, 'rb') if os.path.isfile(host) else None  # 目录:None,供 getcwd 遍历
            fd = self.next_fd
            self.next_fd += 1
            st = os.stat(host)
            self.open_files[fd] = [host, f, os.path.getsize(host) if f else 4096, 0, st]
            self.log(f'   open({path!r}) → fd{fd} ({self.open_files[fd][2]} bytes)')
            return fd, 0
        if num == 6:      # close
            if r0 in self.open_files:
                f = self.open_files[r0]
                if f[1] is not None:
                    f[1].close()
                del self.open_files[r0]
            return 0, 0
        if num == 3:      # read
            if r0 not in self.open_files:
                return self.ret_err(ERRNO_EBADF)
            f = self.open_files[r0]
            if f[1] is None:  # 虚拟随机源
                data = os.urandom(min(r2, 4096))
                self.uc.mem_write(r1, data)
                return len(data), 0
            data = f[1].read(min(r2, f[2] - f[3]))
            f[3] += len(data)
            if data:
                self.uc.mem_write(r1, data)
            self.log(f'   read(fd{r0}, {r2}) → {len(data)}')
            return len(data), 0
        if num in (189, 339, 340):  # fstat / fstat64 / lstat64
            if r0 not in self.open_files:
                return self.ret_err(ERRNO_EBADF)
            host, f, size, pos, st = self.open_files[r0]
            buf = bytearray(128)
            struct.pack_into('<I', buf, 0, st.st_dev & 0xFFFFFFFF)  # st_dev
            struct.pack_into('<H', buf, 8, 0x81ED if f else 0x41ED)  # st_mode
            struct.pack_into('<I', buf, 4, st.st_ino & 0xFFFFFFFF)  # st_ino (old stat)
            struct.pack_into('<I', buf, 16, 501)                    # st_uid
            struct.pack_into('<Q', buf, 48, size)                   # st_size
            struct.pack_into('<I', buf, 60, 4096)                   # st_blksize
            self.uc.mem_write(r1, bytes(buf))
            self.log(f'   fstat(fd{r0}) → size={size} ino={st.st_ino}')
            return 0, 0
        if num == 338 or num == 340:  # stat64 / lstat64
            path = self.read_cstr(r0)
            host = os.path.join(self.rootfs, path.lstrip('/')) if path.startswith('/') else \
                   os.path.join(self.rootfs, path)
            if not os.path.exists(host):
                return self.ret_err(ERRNO_ENOENT)
            st = os.stat(host)
            self.fake_stat64(r1, os.path.getsize(host) if os.path.isfile(host) else 4096, st)
            self.log(f'   stat64({path!r}) → size={os.path.getsize(host) if os.path.isfile(host) else 4096} ino={st.st_ino}')
            return 0, 0
        if num == 197:    # mmap(addr, len, prot, flags, fd, offset)
            addr, length, prot, flags, fd, offset = a
            MAP_ANON, MAP_FIXED = 0x1000, 0x10
            if flags & MAP_ANON:
                base = self.mmap_next
                self.mmap_next = align_up(base + length)
                self.map_range(base, length)
                self.log(f'   mmap(anon, {length:#x}) → {base:#x}')
                return base, 0
            if fd not in self.open_files:
                return self.ret_err(ERRNO_EBADF)
            host, f, fsize, pos = self.open_files[fd]
            if flags & MAP_FIXED and addr:
                base = addr
            else:
                base = self.mmap_next
                self.mmap_next = align_up(base + length)
            self.map_range(base, length)
            f.seek(offset)
            data = f.read(min(length, fsize - offset))
            self.uc.mem_write(base, data)
            f.seek(0)
            self.log(f'   mmap(file {os.path.basename(host)}, {length:#x} @off {offset:#x}) → {base:#x}')
            return base, 0
        if num in (71, 73):   # munmap(两种编号都按 nop)
            return 0, 0
        if num in (74, 75):   # mprotect / madvise
            return 0, 0
        if num == 92:     # fcntl
            fd, cmd, arg = a[0], a[1], a[2]
            if cmd == 50 and fd in self.open_files:  # F_GETPATH:把路径写回缓冲区
                host = self.open_files[fd][0]
                rel = os.path.relpath(host, self.rootfs)
                full = '/' if rel == '.' else '/' + rel
                self.uc.mem_write(arg, full.encode() + b'\x00')
                self.log(f'   fcntl(F_GETPATH, fd{fd}) → {full!r}')
            return 0, 0
        if num == 327:    # issetugid
            return 0, 0
        if num == 20:     # getpid
            return 100, 0
        if num in (24, 25, 47):  # getuid/geteuid 系
            return 501, 0
        if num == 33:     # access
            path = self.read_cstr(r0)
            host = os.path.join(self.rootfs, path.lstrip('/'))
            return (0, 0) if os.path.exists(host) else self.ret_err(ERRNO_ENOENT)
        if num == 294:    # thread_set_tsd_base —— 设置当前线程 TLS(TPIDRURW)
            self.uc.reg_write(UC_ARM_REG_C13_C0_3, r0)
            self.log(f'   thread_set_tsd_base → {r0:#x}')
            return 0, 0
        if num in (295, 438):  # shared_region_map(_and_slide)_np → 让 dyld 走手动 mmap 缓存的回退路径
            self.log('   shared_region_map → 拒绝(引导 dyld 手动映射缓存)')
            return self.ret_err(ERRNO_ENOTSUP)
        self.log(f'   [未实现 BSD syscall {num}] args={["%#x" % x for x in a]}')
        return self.ret_err(ERRNO_ENOTSUP)

    def fake_stat64(self, buf_addr, size, st=None):
        """xnu armv7 struct stat64 布局(字段偏移按 sys/stat.h 推导)"""
        buf = bytearray(160)
        st = st or os.stat(self.rootfs)
        struct.pack_into('<I', buf, 0, st.st_dev & 0xFFFFFFFF)  # st_dev
        struct.pack_into('<H', buf, 4, 0x81ED)                  # st_mode 100755
        struct.pack_into('<H', buf, 6, 1)                       # st_nlink
        struct.pack_into('<Q', buf, 8, st.st_ino)               # st_ino
        struct.pack_into('<I', buf, 16, 501)                    # st_uid
        struct.pack_into('<I', buf, 20, 501)                    # st_gid
        struct.pack_into('<Q', buf, 92, size)                   # st_size
        struct.pack_into('<Q', buf, 100, (size + 511) // 512)   # st_blocks
        struct.pack_into('<I', buf, 108, 4096)                  # st_blksize
        self.uc.mem_write(buf_addr, bytes(buf))

    def mach_trap(self, num, a):
        # Mach 陷阱:编号为负。编号依据 dyld/libsystem 桩代码(mvn ip, #N)反汇编实测。
        if num == -0x80000000:  # sys_icache_invalidate(ARMv7 特殊编号)——Unicorn 无需缓存维护
            return 0, 0
        if num == -10:    # mach_vm_allocate(task, &addr, size, flags)
            size = a[2]
            base = self.mmap_next
            self.mmap_next = align_up(base + max(size, PAGE))
            self.map_range(base, max(size, PAGE))
            self.uc.mem_write(a[1], struct.pack('<Q', base))  # mach_vm_address_t 64 位写回
            self.log(f'   mach_vm_allocate({size:#x}) → {base:#x}')
            return 0, 0
        if num in (-11, -12, -3):  # mach_vm_deallocate / protect / 其它占位
            return 0, 0
        if num == -13:    # mach_vm_map(带 memory object)→ 失败,让 dyld 走 mmap 回退
            self.log('   mach_vm_map → KERN_FAILURE(回退 mmap)')
            return 1, 0
        if num == -26:    # mach_reply_port
            return 1, 0
        if num == -27:    # mach_thread_self
            return 2, 0
        if num == -28:    # mach_task_self
            return 3, 0
        if num == -29:    # mach_host_self
            return 4, 0
        if num == -31:    # mach_msg_trap(armv7)
            self.log(f'   mach_msg(size={a[0]:#x}) → KERN_SUCCESS(占位)')
            return 0, 0
        self.log(f'   [未实现 Mach trap {num}]')
        return 0, 0

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        print(f'\n!! 非法内存访问: {address:#x} (size={size}, pc={pc:#x}, 已执行 {self.instr_count} 次SVC)')
        for name, reg in (('r0', UC_ARM_REG_R0), ('r1', UC_ARM_REG_R1), ('r2', UC_ARM_REG_R2),
                          ('r3', UC_ARM_REG_R3), ('r4', UC_ARM_REG_R4), ('r5', UC_ARM_REG_R5),
                          ('sp', UC_ARM_REG_SP), ('lr', UC_ARM_REG_LR)):
            print(f'   {name} = {uc.reg_read(reg):#010x}')
        print('   最近的 SVC:')
        for spc, snum, sargs in self.svc_history[-10:]:
            print(f'     pc={spc:#x} num={snum} args={["%#x" % x for x in sargs]}')
        return False

    # ---------- 主流程 ----------
    def boot(self, bin_path):
        print(f'== XNU 用户态启动: {os.path.basename(bin_path)} (rootfs={self.rootfs})')
        entry, mh, slide = self.load_macho(bin_path)
        dyld_path = os.path.join(self.rootfs, 'usr/lib/dyld')
        dyld_entry, dyld_mh, _ = self.load_macho(dyld_path)
        # 内核 execve 传入的 argv[0] 是绝对路径,dyld 依赖这一点解析框架搜索
        exec_path = '/' + os.path.relpath(os.path.abspath(bin_path), self.rootfs)
        sp = self.build_stack(mh, [exec_path], [], [])
        print(f'== 跳入真 dyld @ {dyld_entry:#x}, sp={sp:#x}')
        self.uc.reg_write(UC_ARM_REG_SP, sp)
        self.uc.reg_write(UC_ARM_REG_PC, dyld_entry)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0)  # 用户态, ARM 指令集
        try:
            self.uc.emu_start(dyld_entry, 0, count=self.max_instr or 0)
            reason = '正常结束'
        except Exception as e:  # noqa: BLE001
            reason = f'{type(e).__name__}: {e}'
        if self.stopped:
            print(f'\n== 停止: {self.stopped}')
        else:
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            why = '跳转到空指针(emu_start 的 until=0 停止条件)' if pc == 0 else reason
            print(f'\n== 停在 {pc:#x}: {why}')
        print('   -- 最后 64 条指令(pc / lr / sp) --')
        for a, l, s in list(self.ins_hist):
            print(f'     pc={a:#010x} lr={l:#010x} sp={s:#010x}')
        print(f'== 共执行 {self.instr_count} 条真实 ARM 指令')
        print('== 系统调用统计:', dict(sorted(self.syscall_count.items(), key=lambda x: -x[1])[:12]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', required=True, help='rootfs 内的可执行文件路径')
    ap.add_argument('--rootfs', default=os.path.join(os.path.dirname(__file__), '..', 'work', 'rootfs'))
    ap.add_argument('--trace-syscalls', action='store_true')
    ap.add_argument('--trace-code', help='把每条指令的 PC 写入该文件(调试执行流)')
    ap.add_argument('--max-instr', type=int, default=200_000_000)
    args = ap.parse_args()

    emu = XNUUserland(args.rootfs, trace=args.trace_syscalls, max_instr=args.max_instr,
                      code_trace=args.trace_code)
    emu.boot(args.bin)


if __name__ == '__main__':
    main()
