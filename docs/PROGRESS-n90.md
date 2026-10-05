# n90ap (iPhone 4 / S5L8930 / iOS 4.3.1) bring-up progress

Updated: 2026-09-30 (session "sleh_abort forensics")

## Current state: SERIAL OUTPUT WORKS 🎉

Run command (serial + panic output visible):
```
./build/qemu-system-arm -m 512M \
  -M 'n90ap,kcache=/Users/qinsher/ZCodeProject/ios6-emu/work/n90/kernelcache.bin,devicetree=/Users/qinsher/ZCodeProject/ios6-emu/work/n90/devicetree.dec,bootargs=debug=0x14e' \
  -nographic -serial file:/tmp/n90_serial.log -monitor unix:/tmp/n90mon,server,nowait \
  -d int,nochain,guest_errors -D /tmp/n90_all.log
```
- `bootargs=debug=0x14e` (new machine property) makes xnu print panics to
  UART0 even before console init. Serial was always silent before this.
- Kernel banner confirmed: "Darwin Kernel Version 11.0.0 ... xnu-1735.46~2/
  RELEASE_ARM_S5L8930X", panic path works, secure boot = YES.

## Debugging infrastructure added this session (all in n90ap.c / helper.c)
- cpreg write-trace hooks: TTBR0/TTBR1/DACR/TPIDRPRW print every write with
  PC; TTBR hook also dumps new PT L1[C00]/L1[C01]/L1[FFF] and managed L2.
  Use `-d int,nochain,guest_errors -D /tmp/n90_all.log` so these interleave
  with exception logs.
- helper.c: data aborts log faulting pc/lr/sp/mode; UDEF logs pc+insn word.
- Machine bootargs property (`bootargs=`), falls back to kernel_cmdline.

## Boot facts established (ground truth from traces)
- start.s boot PT base = **0x41000000** (TTBR0=0x41000018, 0x18 = RGN bits).
  L1[0xC00] @ PA 0x41003000. Machine pre-patch (n90_patch_bootpt) SURVIVES
  start.s (bzero only covers part) — verified L1[C00]=0x4000040e at switch.
- DACR = 0x00000001 (only domain 0 = client).
- Kernel switches TTBR0 <- **0x41004000** (= cpu_ttb = gTopOfKernel+0x4000)
  at pc 0x8006cc68, AFTER building its own L1+L2s. gdbstub PT patches are
  therefore useless (overwritten by kernel PT build).
- Kernel's own PT: L1[C00]=0x41009001 (coarse) — **managed window L2 starts
  EMPTY by design** (on-demand). VA space of kernel map starts at
  **0xC0001000** (pmap_bootstrap virt_begin = MANAGED_BASE+0x1000).
- UART0 physical on S5L8930 = **0x82500000** (bit31 alias space). Kernel
  io_maps it: managed L2[0] = 0x82500013 (VA 0xC0000000 -> PA 0x82500000).
  QEMU bus alias maps this to our UART at 0x02500000 ✓.
- TPIDRPRW = 0x8029f720 (set at pc 0x8006cb68). [+0x364] = exception stack
  top = **0 (never initialized)**. [+0x368] -> P=0x80287000, [P+8] =
  0x80284000 = IRQ-stack-detection top. Boot stack (start.s sp =
  0x80283FB0) lives INSIDE the detection window (0x80280000..0x80284000).
- fleh (0x8006a368 data-abort vector): kernel-mode aborts keep the
  interrupted thread's SP and push the frame there; then `bl 0x8006ff10`
  (sleh, ARM code).
- ml_at_interrupt_context (0x8006c52c): returns TRUE iff
  top-0x4000 < sp < top where top=[[TPIDRPRW+0x368]+8].

## The blocking bug (solved -> new bug exposed)
- OLD blocker: first kernel data abort (IOKit code reading kmem page
  VA 0xC0001000 — normal on-demand fault) hit "sleh_abort at interrupt
  context" trap.c:501 panic because ml_at_interrupt_context false-positived
  on the boot stack.
- FIX APPLIED: n90_patch_ml_at_interrupt_context() overwrites the check
  (VA 0x8006c52c, Thumb) with `movs r0,#0; bx lr`. Panic gone.
- NEW blocker: after the first abort is dispatched, sleh's kernel-abort
  path calls current_thread()/vm_fault machinery which dereferences a NULL
  global at VA **0x802beca0** (heavily referenced, 118 literals — looks
  like cpu_data_ptr[] or similar per-cpu table; [ptr+0x2c] read at pc
  0x800701f4, lr 0x8006ff54). DFAR 0x2c, DFSR 0x5 (translation fault) —
  infinite recursion pushing 0xE4 bytes per iteration down the boot stack
  until it eats the exception text area 0x8006ff1c+ (spsr 0x600000d3 etc.
  written over code -> UDEF on 0xfffffbfd garbage, CDP p0-like decodes).
- Watchpoint on 0x802beca0 in progress (was it ever written? by whom?).

## Next steps
1. Finish watchpoint: find whether kernel ever writes 0x802beca0 and which
   PC. If never: our bootargs/DT path skips the init that fills it (compare
   with Corellium's xnu cpu_data_start / arm_init flow). If written LATE
   (after IOKit runs): init order issue.
2. Then likely: rerun without the ml_at_interrupt_context patch to see if
   it's still needed (kernel may init stacks later), tune epoch, and wire
   tick IRQ (vic3 line 15 = irq 111).
3. Panic-fix loop toward single-user shell (Milestone A).
4. Kill QEMU after every run (user rule).

## Files
- hw/arm/n90ap.c — machine + cpreg traces + kernel patches
- target/arm/helper.c — exception logging (fault at pc / undef at pc)
- This file + /tmp logs (n90_all.log = interleaved trace, n90_serial.log).
