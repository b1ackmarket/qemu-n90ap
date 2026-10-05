# iPad2,1 (k93ap/A5) 整机仿真 — 工作日志

## 当前状态（里程碑 A 攻坚中）

**内核已通过全部早期启动阶段，正在 kext 构造函数阶段执行。**
这是重大突破：XNU 内核在 QEMU 里真实运行，已完成:
- 入口汇编 → bootargs 解析（含 epoch=0x12 校验）
- 自举页表构建 + MMU 开启（VA 0x80 窗口 = PA 0x40 + 0x40000000）
- 设备树初始化（DTInitDeviceTree 成功，能查找 "arm-io" 节点）
- pe_identify_machine 通过
- OSLibkernInitialize（C++ 静态构造函数）执行中

## 关键发现（这是几小时逆向的成果，勿丢失！）

### 1. 内存地图（从 start.s 逆向证实）
```
DRAM 物理基址 = 0x40000000
内核虚拟链接地址 = 0x80001000（mach-o vmaddr 就是 VA！）
ptovirt 偏移 gVirtBase = 0x40000000（VA = PA + 0x40000000）
内核 VM 区 VM_MIN_KERNEL_ADDRESS = 0xC0000000（= PA 0x80000000 的别名）
QEMU RAM = 2GB @ PA 0x40000000（-m 2048M，覆盖整个 VA 窗口映射目标）
```

### 2. boot_args 关键字段（xnu-2107 实际语义！）
```
+0x00 u16 Revision = 2
+0x02 u16 Version/Epoch = 0x12  ← pe_identify_machine 校验！不匹配会打
                                   "pe_identify_machine: Epoch Mismatch" 并
                                   在后续锁未初始化处挂死
+0x04 u32 virtBase = 0x80000000   ← VA 窗口基址
+0x08 u32 physBase = 0x40000000   ← DRAM 基址
+0x0C u32 memSize = 0x20000000    ← 512MB
+0x10 u32 topOfKernelData = 0x40DA0000 ← 引导页表放这里（PA！）
+0x14 Video...（24B，全 0 即可）
+0x2C machineType = 0
+0x30 deviceTreeP = 0x8F000000   ← VA！DT 实际放 PA 0x4F000000
+0x34 deviceTreeLength = 0x11FD8
+0x38 CommandLine[256]（"-v" 可加）
+0x138 bootFlags = 0
+0x13C memSizeActual = 0x20000000
```
r0 传给内核 = bootargs 的**物理地址** PA 0x4FF01000。
内核入口自己换算: args_va = args_pa - [+8] + [+4]。

### 3. 内核入口 start()（VA 0x800860C8，PA 0x400860C8）行为
```
TTB = topOfKernelData | 0x4A（物理地址！）
清零 TTB 起 40KB（L1 16KB + L2 24KB）
填充循环: for (pa = [+8]; memSize -= 1MB): L1[[+4]>>20 + n] = pa|flags
   → VA [+4]=0x80000000 起 512MB → PA [+8]=0x40000000 起 512MB
   注意: cmp r3(1MB), sl(memSize) 是 **有符号比较 bgt**，
   memSize 必须为正且 < 0x80000000，否则走 4KB L2 慢路径（坏！）
PC 段恒等映射: L1[pc>>20] = (pc & 0xFFF00000)|flags
高向量页: L1[0xFFF] = L2@(TTB+0x9000)，映射 VA 0xFFFF0000
TTB0=TTB1 同值；SCTLR |= 0x3800|0xD（M C W Z I V 高向量！）
结尾: sub r0, r0, r8; add r0, r0, sb   ← 把 args 从 PA 换成 VA
最后 bx lr → lr = __nl_symbol_ptr 里的 0x80017C41（arm_init 前导）
```
boot PT 填充映射后，VA 0xC0000000 **未被映射** —— 但 arm_vm_init 会写它
（pmap 结构, str r5,[0xC0000000]，VM_MIN_KERNEL 编译常量）。
**QEMU 侧对策：机器直接给 2GB RAM @ PA 0x40000000，VA 0xC0 的访问
在 arm_vm_init 自己的二级页表生效前，靠内核后续的页表切换。**
（实测: 内核成功活过 arm_vm_init、DT walk、进入 kext 构造函数阶段！）

### 4. 设备树（DeviceTree.k93ap.img3）解析结果 = A5 完整硬件地图
- AIC: "aic,1" @ 0x0F200000 (0x10000)，驱动 AppleInterruptController @0x80ABF000
  日志串: "AppleInterruptController::start: _aicVersion = %d ..."
- UART0: "uart-1,samsung" @ 0x2500000, irq 21（exynos4210_uart 兼容）
- PMGR: @ 0xF100000 (0x7000) + 0x8C00000/8D/8E/8F/A5/A6
- GPIO: @ 0xFA00000; WDT: @ 0xF103020 irq 4
- NAND: "fmi,s5l8940x" @ 0x1200000 (6 窗口) irq 33,34
- SGX: @ 0x5100000; CLCD @ 0xA100000; MIPI @ 0x9500000
- I2C0/1/2: @ 0x3200000/3300000/3400000，PMU = d1946 @ i2c0 addr 0x3C
- DRAM: 512MB（memory 节点 reg 需补丁为 0x40000000/0x20000000！）

### 5. 构建工具链（全部在 qemu-ios/build）
```
cd build && ninja qemu-system-arm
./arm-softmmu/qemu-system-arm -m 2048M \
  -M 'k93ap,kcache=/Users/qinsher/ZCodeProject/ios6-emu/work/img3/kernelcache.bin,devicetree=/Users/qinsher/ZCodeProject/ios6-emu/work/img3/devicetree.dec' \
  -nographic -serial file:/tmp/k93_serial.log -monitor unix:/tmp/k93mon,server,nowait \
  -d unimp -D /tmp/k93_unimp.log
```
调试: `-S -s` + `lldb -b -s cmds.txt`（gdb-remote localhost:1234）；
`-d int,in_asm,nochain` 抓首异常；QMP dump-guest-memory 抓 RAM 快照。
注意 lldb 输出缓冲：脚本最后必须加 quit，输出用 grep 过滤。

### 6. 踩过的坑（重要！）
- **段加载必须按 LC_SEGMENT 逐段**：裸 memcpy 整个文件会把 __LINKEDIT
  （symtab/字符串）泼到 __bss/__common 上，毁掉所有零初始化全局变量
  （DT 状态、自旋锁、PE_state 全烂，症状是 "Sour" 字符串当指针！）
- LZSS 解压: complzss 头 0x180 字节，Okumura 变体（4096 环形字典、
  空格初始化、dictptr=4078、长度=低半字节+3）。已验证与 lzssdec 字节一致。
- IMG3 魔数是小端 "3gmI"（反向读 "Img3"）
- bootargs [+2] 必须是 0x12（"Epoch"），否则 kprintf 在锁初始化前被调用
- HMP `pmemsave` 在本 fork 报 "invalid char"，用 QMP dump-guest-memory
- lldb 对 PA 断点有时挂起；用 `-d int` 日志和 QMP 转储更可靠

## 下一步（按优先级）
1. **AIC 中断控制器**（0xF200000）：实现寄存器语义，让定时器中断进来。
   参考线索: AppleInterruptController kext（VA 0x80ABF000 附近代码），
   日志串 "start: _aicVersion = %d ..."。Linux irq-apple-aic.c 只有 AIC2。
   实证法: unimp 日志看内核访问序列 → 推寄存器语义。
2. **定时器**: 设备树无 timer 节点 → 很可能在 PMGR 块内或 AIC 内。
   iBoot 二进制（work/img3/iboot.dec）有初始化代码可逆向。
3. **串口 console**: exynos4210_uart @ 0x2500000 应该兼容 samsung uart-1。
   内核 console 驱动起来后应输出 "Darwin Kernel Version 13.0.0..." 横幅。
4. panic 修跑循环 → rd=md0 ramdisk 或 rootfs → 单用户 shell = 里程碑 A。

## 产物位置
- qemu-ios/hw/arm/k93ap.c = 机器模型（已进 build：-M k93ap）
- ios6-emu/work/img3/kernelcache.bin = 解压后内核（13.9MB, 已验证）
- ios6-emu/work/img3/devicetree.dec = 已解密 DT（memory 节点已补丁）
- ios6-emu/work/img3/{iboot,llb}.dec = 解密后的引导程序
- ios6-emu/emu/img3_decrypt.py = IMG3 解密器
- ios6-emu/work/keys_iPad2,1_10B329.json = 全部组件密钥
