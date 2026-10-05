# qemu-n90ap — iPhone 4 (N90AP / S5L8930) iOS 4.3.1 XNU boot bring-up

在 QEMU 中直接引导 **iOS 4.3.1 XNU 内核**(xnu-1735, Darwin 11.0.0,
RELEASE_ARM_S5L8930X)的研究成果归档。

本项目只包含**可复用的增量成果**(机器模型、补丁、工具、调试记录),
完整的 QEMU 基础树与 iOS 固件均**不在此仓库**,见下方「用到的 QEMU」。

## 仓库内容

| 路径 | 说明 |
|---|---|
| `hw/arm/n90ap.c` | **核心机器模型**:iPhone 3,1 (N90AP / S5L8930X "A4"),直接引导内核收藏 |
| `hw/arm/k93ap.c` | 同一框架的 iPad 2,1 (A5) 机器模型 |
| `patches/qemu-ios-n90ap.patch` | 对 QEMU fork 的全部必要改动(机器注册 + 调试设施) |
| `tools/dt_inject_ramdisk.py` | 设备树 RAMDisk 属性注入工具(内核 rd=md0 根设备路径) |
| `docs/PROGRESS-n90.md` | 每会话的调试过程与地面真相 |

## 机器布局

模拟了 iBoot 启动内核时留下的状态(n90ap.c 内建):

```
DRAM      512 MB  @ 0x40000000, 内核窗口 VA = PA + 0x40000000
内核        VA 0x80001000   →  PA 0x40001000 (从 LC_UNIXTHREAD 取 entry)
设备树      VA 0x8F000000   →  PA 0x4F000000
boot_args  PA 0x4FF01000   (r0 = &boot_args, 物理)  命令名 "debug=0x14e io=0xffff"
RAMDisk    PA 0x50000000   (打开 N90_RAMDISK=<文件> 自动 staging)
start.s 临时页表 PA 0x41000000, 机器会补齐 VA 0xC0000000 → PA 0x40000000 别名窗口
VIC×4     PL192 @ 0x3F200000, stride 0x10000; UART0-5 @ 0x2500000 + n*0x100000,
          IRQ 22..27; tick 定时器 @ 0x3F102000 (24 MHz)
```

## 运行

需要先取得: iOS 4.3.1 的 `kernelcache.bin` 与 `devicetree.dec`(Apple
固件, 从 IPSW 中解密, 本仓库不含), 以及 QEMU 基树(见下)。

```bash
# 1) 应用补丁到 QEMU: 把两个 machine 源文件放入 carry, 打 patch, 编译
# 2) 注入 RAMDisk(可选, rd=md0 根设备):
python3 tools/dt_inject_ramdisk.py \
    devicetree.dec 0x50000000 20148256 devicetree.ramdisk
# 3) 启动
N90_RAMDISK=rd.raw ./qemu-system-arm \
  -M 'n90,kcache=kernelcache.bin,devicetree=devicetree.ramdisk,\
      bootargs=debug=0x14e io=0xffff rd=md0' \
  -serial file:/tmp/serial.log -monitor none -nographic
```

## 用到的 QEMU

基础树是社区 Apple SoC 移植 fork **devos50/qemu-ios**
(https://github.com/devos50/qemu-ios), 含 ipod_touch_2g 等前置工作。
本项目在其 `arm-softmmu` 主线上新增 `n90ap` / `k93ap` 两台机器;
相对该 fork 的全部差异见 `patches/qemu-ios-n90ap.patch`:

- `configs/devices/arm-softmmu/default.mak`, `hw/arm/Kconfig`,
  `hw/arm/meson.build` — 注册新机器
- `hw/intc/pl192.c` — VIC 中断线路日志(FIQ 排查用, 可关闭)
- `target/arm/helpers.c` — 异常地址的 pc/lr/sp 日志(可关闭)

iOS 固件(内核、DT)与解密工具不在此仓库 — 版权与体积原因。

## 进度(2026-10-05 归档)

- ✅ 串口输出、panic 路径、bootargs 解析、DT/内核加载
- ✅ 绕过启动期 `ml_at_interrupt_context` 误判 panic
- ✅ 定位并绕过 `IOFindBSDRoot` 的 "md0 未配置" panic(打补丁 NOP)
- ✅ 抓出根设备等待卡点:`IOSurfaceRoot::installMemoryRegions()` 之后
  boot 停在 `qst=4/6` 的 root-device 等待, `rd=md0` 内存盘已注好
  但尚未走到 "Added memory device md0" 打印 — 见 PROGRESS 的"下一步"
- ○ 目标里程碑 A(launchd → 单用户串行控制台)未完结, 项目于此归档