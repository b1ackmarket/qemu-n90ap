# ios6-emu —— iOS 6 真模拟器工作台(归档子项目)

> **归档说明**:本目录原是独立工作区 "ios6-emu"(iOS 6 方向的研究台),现作为
> [qemu-n90ap](../README.md) 的姊妹子项目归档。这里只收纳**代码与记录**;
> 固件本体(IPSW、解密后的 rootfs、kernelcache、密钥 json)均**不在此仓库**
> ——版权与体积原因,也在本 README 末尾的法律声明约定之内。

目标:吃进一套 iOS 6 的 **IPSW**,在其上**真实执行**应用(最终形态:QEMU 仿真 A5 SoC 启动
XNU 内核 + 完整用户态,像 Corellium 那样跑 IPA)。

这是一个研究级工程,按**三层阶梯**组织,每层独立可用、可验证。**原工作区状态:Layer 1 完成
(在 iPad2,1 6.1.3 10B329 实机固件上全流程验证),Layer 2 骨架运行中。**

```
┌─ Layer 3  内核层   QEMU 仿真 S5L8940X(A5) 启动 XNU + SpringBoard + 图形栈
│            研究前沿:开源界尚无 iOS 6 带图形的完整启动;本层是长期目标
├─ Layer 2  用户态层 emu/xnu_boot.py —— Unicorn(真 ARMv7 CPU 逐指令仿真)启动
│            真 dyld,由 dyld 自己完成 Mach-O 加载/共享缓存映射/符号绑定
│            ✅ 已运行:真 dyld 的 mach_init、stack-guard(/dev/random)、
│                      getcwd(真实文件系统遍历)、加载命令扫描……
│            ⏳ 进行中:Mach IPC、commpage 例程表、线程/TLS、缓存映射路径
└─ Layer 1  固件层   ✅ 完成:IPSW 解包 → theiphonewiki 查密钥 → 解密 rootfs DMG
                      → 挂载展开 → 完整 iOS 6.1.3 文件系统(1.4GB)
```

## 快速开始(已在 iPad2,1_6.1.3_10B329 上全程验证)

```bash
./setup.sh                                    # ipsw CLI + venv 里的 qiling/unicorn/pycryptodome
./scripts/01_extract.sh <iOS6.ipsw>           # 解包(iPhoneOS 6 时代 IMG3,直接按 ZIP 解)
./scripts/02_decrypt.sh                       # 查密钥 + 解密 rootfs("encrcdsa" FileVault-V2)
./scripts/03_rootfs.sh                        # 挂载 → work/rootfs/ 完整 iOS 文件系统
./scripts/04_dsc.sh                           # 解析 dyld 共享缓存(569 个镜像)

# Layer 2:在真 CPU 仿真上启动 iOS 6 真实 dyld + launchd:
.venv/bin/python3 emu/xnu_boot.py --bin work/rootfs/sbin/launchd --trace-syscalls

# IPA 静态分析(架构 / FairPlay / 链接框架):
.venv/bin/python3 emu/run_binary.py --rootfs work/rootfs --ipa <应用>.ipa --info
```

注:固件与解密密钥需自行准备(iOS 6 IPSW、theiphonewiki 密钥),仓库不提供。

## 技术要点(实战验证过的坑)

| 问题 | 答案 |
|---|---|
| iOS 6 rootfs DMG 加密 | `encrcdsa`(FileVault V2):按 512 字节分块 AES-128-CBC,每块 IV = HMAC-SHA1(hmacKey, chunkNo)[:16];密钥串 72 位 hex = AES key(32) + HMAC key(40)。实现见 `emu/dmg_decrypt.py`,与正式 vfdecrypt 逐字节一致 |
| 新版 ipsw CLI 解析 IMG3 | 不支持(只认 IM4P/IMG4)。解包用 unzip,解密用上面的实现 |
| iOS 6 的框架二进制 | 全部在 `dyld_shared_cache_armv7`(磁盘上的 .framework 只有资源),解析见 `emu/dsc_list.py` |
| Unicorn ARM 跑 NEON | 默认 VFP/NEON 关闭,必须设置 CPACR |= 0xF00000 和 FPEXC.EN,否则 `vst1` 报 INVALID |
| Unicorn 的 SVC 语义 | INTR 钩子触发时 PC 已越过 SVC 指令,不要自己再前进 |
| dyld 启动栈契约 | dyld-210.2.3 `_dyld_start`:`[sp+0]`=主程序 **mach header 的栈上副本**(内核 exec 压入,含全部 load commands)、`[sp+4]`=argc、`[sp+8]`=argv;argv[0] 必须是绝对路径 |
| armv7 Mach 陷阱编号 | 实测(来自 libsystem 桩 `mvn ip,#N`):-26 reply_port / -27 thread_self / -28 task_self / -29 host_self / -10 mach_vm_allocate / `0x80000000` = sys_icache_invalidate |

## Layer 3 说明与关键参考:[devos50/qemu-ios](https://github.com/devos50/qemu-ios)

**有人把整条 Layer 3 路线走通了(上一代硬件)**:该 QEMU fork 模拟 iPod Touch 1G/2G
(S5L8900/S5L8720, ARM11),**启动到主屏幕(SpringBoard 出画面)**,SDL 显示、键鼠代替触摸。
⚠️ 注意:启动的是**原生固件 + 原生 CPU 代际**的完整系统仿真;`hw/arm/` 下有 28 个逆向
外设文件(机型模型、中断控制器、时钟、GPIO、NAND、SPI NOR、PowerVR MBX GPU、LCD/多点触摸、
USB、PMU、AES/MD5/SHA1 引擎等),是"Apple SoC 需要仿什么"的完整清单与逆向方法论。

这对本项目的意义:同框架移植。qemu-n90ap 的 `n90ap`(iPhone 4 / A4)与 `k93ap`(iPad 2 / A5)
机型正是建立在该 fork 之上,见 [../README](../README.md)。

## 法律

固件由 Apple 版权所有:密钥与固件在 [theiphonewiki](https://theiphonewiki.com) 均为公开资料,
本工具链仅用于个人存档/研究,请不要再分发固件或 rootfs 内容。