/*
 * iPhone 3,1 "N90AP" (S5L8930X "A4") minimal machine model.
 *
 * Boots the iOS 4.3.1 XNU kernelcache directly by emulating the state iBoot
 * leaves behind: kernel mapped VA 0x80001000 -> PA 0x40001000, flattened
 * device tree at VA 0x8F000000 (PA 0x4F000000), boot_args at PA 0x4FF01000,
 * r0 = &boot_args (physical), pc = kernel entry point from LC_UNIXTHREAD.
 *
 * The n90 device tree confirms the alias window:
 *   arm-io ranges = { child 0x80000000, size 0x40000000 -> parent 0x40000000 }
 * i.e. VA = PA + 0x40000000 for the kernel window, and start.s maps
 * VA[virtBase] -> PA[physBase] per 1MB section for memSize bytes.
 *
 * Peripherals (from the n90ap flattened device tree):
 *   VIC  x4 (PL192): 0x3F200000, stride 0x10000 ("vic", "arm,vic")
 *   UART0-5 (samsung): 0x2500000 + n*0x100000, IRQ 22..27
 *   PMGR ("pmgr,s5l8930x", device_type "timer"): 0x3F100000, 0x6000
 *   GPIO: 0x3FA00000   PWM: 0x3500000   arm-io (chip-rev): 0xBFC00000
 *
 * Usage:
 *   qemu-system-arm -M n90ap,kcache=kernelcache.bin,devicetree=devicetree.dec
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "qemu/log.h"
#include "hw/misc/unimp.h"
#include "hw/irq.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "hw/qdev-clock.h"
#include "qemu/error-report.h"
#include "hw/boards.h"
#include "target/arm/cpu.h"
#include "target/arm/cpregs.h"
#include "exec/exec-all.h"
#include "exec/address-spaces.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "hw/arm/exynos4210.h"
#include "hw/intc/pl192.h"

#define N90_RAM_BASE        0x40000000ULL
#define N90_RAM_SIZE        0x20000000ULL   /* 512 MB of DRAM (iPhone 4) */
#define N90_VIRT_OFFSET     0x40000000ULL   /* va = pa + 0x40000000 */
#define N90_KERNEL_VA       0x80001000ULL
#define N90_DT_VA           0x8F000000ULL
#define N90_DT_PA           (N90_DT_VA - N90_VIRT_OFFSET)
#define N90_BOOTARGS_PA     0x4FF01000ULL
#define N90_RAMDISK_PA      0x50000000ULL
#define N90_TOPOFKERNEL     0x41000000ULL   /* TTB, well above the kernel image */

#define N90_PMGR_BASE       0x3F100000ULL
#define N90_PMGR_SIZE       0x6000ULL
#define N90_VIC_BASE        0x3F200000ULL
/* Community ground truth (winocm QEMU-s5l89xx-port s5l8930.h):
 * S5L8930_VIC_BASE 0x3F200000, S5L8930_VIC_SHIFT 0x10000, 4 VICs
 * (the DT "vic" reg <0x3f200000 0x40000> spans all four). */
#define N90_VIC_STRIDE      0x10000ULL
#define N90_NUM_VICS        4
#define N90_IRQS_PER_VIC    32

static const uint64_t n90_uart_base[6] = {
    0x2500000ULL, 0x2600000ULL, 0x2700000ULL,
    0x2800000ULL, 0x2900000ULL, 0x2A00000ULL,
};
static const int n90_uart_irq[6] = { 22, 23, 24, 25, 26, 27 };

/* boot_args (pexpert/pexpert/arm/boot.h) */
#define BOOT_LINE_LENGTH    256
typedef struct BootArgs {
    uint16_t Revision;
    uint16_t Version;
    uint32_t virtBase;
    uint32_t physBase;
    uint32_t memSize;
    uint32_t topOfKernelData;
    /* Boot_Video (pexpert Boot_Video order: base, display, rowBytes, w, h, depth) */
    uint32_t video_v_base;
    uint32_t video_v_display;
    uint32_t video_v_rowBytes;
    uint32_t video_v_width;
    uint32_t video_v_height;
    uint32_t video_v_depth;
    uint32_t machineType;
    uint32_t deviceTreeP;
    uint32_t deviceTreeLength;
    char CommandLine[BOOT_LINE_LENGTH];
    uint32_t bootFlags;
    uint32_t memSizeActual;
} QEMU_PACKED BootArgs;

typedef struct N90MachineState {
    MachineState parent;
    char kcache_path[512];
    char dtree_path[512];
    ARMCPU *cpu;
    qemu_irq irq[N90_NUM_VICS * N90_IRQS_PER_VIC];
    uint64_t kernel_entry;
    uint16_t epoch;
    char *bootargs;
} N90MachineState;

#define TYPE_N90_MACHINE MACHINE_TYPE_NAME("n90ap")
OBJECT_DECLARE_SIMPLE_TYPE(N90MachineState, N90_MACHINE);

/* A4 = Cortex-A8 with an external PL310 reached through cp15 c9 (opc1=1).
 * QEMU's cortex-a8 leaves those encodings undefined; the kernel's start.s
 * touches them unconditionally, so provide read-as-zero/write-ignored
 * stand-ins (same idea as the ipod_touch_2g cpreg overrides). */
/* Early-boot page-table forensics: log every TTBR/DACR write so we can tell
 * which translation table is active when the kernel takes an abort. */
static uint64_t n90_ttbr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return ri->opc2 == 0 ? env->cp15.ttbr0_s : env->cp15.ttbr1_s;
}

static void n90_ttbr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    int which = ri->crn == 2 && ri->opc2 == 0 ? 0 : 1;
    qemu_log_mask(LOG_GUEST_ERROR, "n90: TTBR%d <- 0x%08llx (pc 0x%08x)\n", which,
                  (unsigned long long)value, env->regs[15] & ~1u);
    env->cp15.ttbr0_s = value;
    env->cp15.ttbr0_ns = value;
    env->cp15.ttbr1_s = value;
    env->cp15.ttbr1_ns = value;
    if (which == 0 && (value & 0xFFFFC000u)) {
        /* Show what the kernel itself built for the managed window before
         * it switches to this table. */
        hwaddr base = value & 0xFFFFC000u;
        uint32_t e_c00 = ldl_phys(&address_space_memory, base + 0xC00 * 4);
        uint32_t e_c01 = ldl_phys(&address_space_memory, base + 0xC01 * 4);
        uint32_t e_fff = ldl_phys(&address_space_memory, base + 0xFFF * 4);
        qemu_log_mask(LOG_GUEST_ERROR,
                      "n90:   new PT L1[C00]=0x%08x L1[C01]=0x%08x L1[FFF]=0x%08x\n",
                      e_c00, e_c01, e_fff);
        if ((e_c00 & 3) == 1) {
            /* Coarse L2: print entries for the first pages of VA 0xC000xxxx. */
            hwaddr l2 = e_c00 & 0xFFFFFC00u;
            qemu_log_mask(LOG_GUEST_ERROR,
                          "n90:   L2@0x%08llx [0]=0x%08x [1]=0x%08x [2]=0x%08x\n",
                          (unsigned long long)l2,
                          ldl_phys(&address_space_memory, l2 + 0),
                          ldl_phys(&address_space_memory, l2 + 4),
                          ldl_phys(&address_space_memory, l2 + 8));
        }
    }
    tlb_flush(env_archcpu(env));
}

static uint64_t n90_dacr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->cp15.dacr_s;
}

static void n90_dacr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    qemu_log_mask(LOG_GUEST_ERROR, "n90: DACR <- 0x%08llx (pc 0x%08x)\n",
                  (unsigned long long)value, env->regs[15] & ~1u);
    env->cp15.dacr_s = value;
    env->cp15.dacr_ns = value;
    tlb_flush(env_archcpu(env));
}

static void n90_tpidrprw_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    uint32_t top = 0;
    hwaddr percpu = value & 0xFFFFFFFEu;
    if (percpu) {
        /* TPIDRPRW holds a kernel VA; ldl_phys needs the DRAM PA.
         * Two windows: kernel image VA = PA + 0x40000000, managed/RAM
         * window 0xC0000000+ = PA + 0x80000000. */
        if (percpu >= 0xC0000000u) {
            percpu -= 0x80000000u;
        } else if (percpu >= N90_VIRT_OFFSET) {
            percpu -= N90_VIRT_OFFSET;
        }
        top = ldl_phys(&address_space_memory, percpu + 0x368);
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "n90: TPIDRPRW <- 0x%08llx (pc 0x%08x) irq_stack_top=[+0x368]=0x%08x\n",
                  (unsigned long long)value, env->regs[15] & ~1u, top);
    env->cp15.tpidrprw_s = value;
    env->cp15.tpidrprw_ns = value;
    tlb_flush(env_archcpu(env));
}

static uint64_t n90_tpidrprw_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->cp15.tpidrprw_s;
}

static const ARMCPRegInfo n90_cp_reginfo[] = {
    { .name = "N90_TTBR0_TRACE", .cp = 15, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = n90_ttbr_read, .writefn = n90_ttbr_write },
    { .name = "N90_TTBR1_TRACE", .cp = 15, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = n90_ttbr_read, .writefn = n90_ttbr_write },
    { .name = "N90_TPIDRPRW_TRACE", .cp = 15, .crn = 13, .crm = 0, .opc1 = 0, .opc2 = 4,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = n90_tpidrprw_read, .writefn = n90_tpidrprw_write },
    /* The kernel reads MRC p15,<opc1=3>,Rt,c13,c0,<opc2> somewhere in its
     * per-cpu accessors; Cortex-A8 accepts it, QEMU has no definition and
     * the resulting UND handler corrupts itself.  Alias the whole bank to
     * TPIDRPRW (per-cpu base pointer). */
    { .name = "N90_C13_OPC1_3", .cp = 15, .crn = 13, .crm = 0, .opc1 = 3, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = n90_tpidrprw_read, .writefn = n90_tpidrprw_write },
    { .name = "N90_C13_OPC1_3B", .cp = 15, .crn = 13, .crm = 0, .opc1 = 3, .opc2 = 4,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = n90_tpidrprw_read, .writefn = n90_tpidrprw_write },
    { .name = "N90_DACR_TRACE", .cp = 15, .crn = 3, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .readfn = n90_dacr_read, .writefn = n90_dacr_write },
    { .name = "N90_L2AUXCTL", .cp = 15, .crn = 9, .crm = 0, .opc1 = 1, .opc2 = 2,
      .access = PL1_RW, .type = ARM_CP_CONST | ARM_CP_OVERRIDE, .resetvalue = 0 },
    { .name = "N90_C15VOODOO", .cp = 15, .crn = 15, .crm = 2, .opc1 = 0, .opc2 = 4,
      .access = PL1_RW, .type = ARM_CP_CONST | ARM_CP_OVERRIDE, .resetvalue = 0 },
    { .name = "N90_DCINV0", .cp = 15, .crn = 7, .crm = 6, .opc1 = 0, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NOP | ARM_CP_OVERRIDE },
    { .name = "N90_DCCI0", .cp = 15, .crn = 7, .crm = 14, .opc1 = 0, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NOP | ARM_CP_OVERRIDE },
    { .name = "N90_DCC0", .cp = 15, .crn = 7, .crm = 10, .opc1 = 0, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NOP | ARM_CP_OVERRIDE },
};

static uint64_t kernel_entry_from_macho(const uint8_t *data, size_t size)
{
    uint32_t magic, ncmds;
    if (size < 32) return 0;
    magic = ldl_le_p(data);
    if (magic != 0xfeedface) { /* MH_MAGIC */
        error_report("n90ap: kernel is not a 32-bit LE Mach-O (magic %08x)", magic);
        return 0;
    }
    ncmds = ldl_le_p(data + 16);
    size_t off = 28;
    for (uint32_t i = 0; i < ncmds && off + 8 <= size; i++) {
        uint32_t cmd = ldl_le_p(data + off);
        uint32_t cmdsize = ldl_le_p(data + off + 4);
        if (cmdsize < 8 || off + cmdsize > size) break;
        if (cmd == 5) { /* LC_UNIXTHREAD */
            if (cmdsize >= 8 + 4 + 4 + 17 * 4) {
                return ldl_le_p(data + off + 16 + 15 * 4); /* pc */
            }
        }
        off += cmdsize;
    }
    return 0;
}

static void n90_load_kernel(N90MachineState *s, AddressSpace *as)
{
    uint8_t *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(s->kcache_path, (char **)&data, &size, NULL)) {
        error_report("n90ap: cannot read kernelcache '%s'", s->kcache_path);
        exit(1);
    }
    if (size > N90_RAM_SIZE) {
        error_report("n90ap: kernelcache too large: %zu", (size_t)size);
        exit(1);
    }
    s->kernel_entry = kernel_entry_from_macho(data, size);
    if (!s->kernel_entry) {
        error_report("n90ap: no LC_UNIXTHREAD entry point found");
        exit(1);
    }
    /* Load per LC_SEGMENT: copy [fileoff, filesize) to vmaddr - VIRT_OFFSET,
     * leave BSS (vmsize > filesize) as zeroes. A raw file copy would splatter
     * __LINKEDIT over __bss/__common and corrupt every zero-init global. */
    uint32_t ncmds = ldl_le_p(data + 16);
    size_t off = 28;
    uint64_t loaded = 0;
    for (uint32_t i = 0; i < ncmds && off + 8 <= size; i++) {
        uint32_t cmd = ldl_le_p(data + off);
        uint32_t cmdsize = ldl_le_p(data + off + 4);
        if (cmdsize < 8 || off + cmdsize > size) break;
        if (cmd == 1) { /* LC_SEGMENT */
            uint32_t vmaddr = ldl_le_p(data + off + 24);
            uint32_t vmsize = ldl_le_p(data + off + 28);
            uint32_t fileoff = ldl_le_p(data + off + 32);
            uint32_t filesize = ldl_le_p(data + off + 36);
            if (filesize > vmsize) filesize = vmsize;
            uint64_t pa = vmaddr - N90_VIRT_OFFSET;
            if (fileoff + filesize <= size && pa >= N90_RAM_BASE &&
                pa + vmsize <= N90_RAM_BASE + N90_RAM_SIZE) {
                address_space_rw(as, pa, MEMTXATTRS_UNSPECIFIED,
                                 data + fileoff, filesize, 1);
                loaded += filesize;
            }
        }
        off += cmdsize;
    }
    info_report("n90ap: kernel %zu bytes, segments loaded %llu bytes, entry 0x%08llx",
                (size_t)size, (unsigned long long)loaded,
                (unsigned long long)s->kernel_entry);
    g_free(data);
}

static void n90_load_dtree(N90MachineState *s, AddressSpace *as, uint32_t *dt_len)
{
    uint8_t *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(s->dtree_path, (char **)&data, &size, NULL)) {
        error_report("n90ap: cannot read devicetree '%s'", s->dtree_path);
        exit(1);
    }
    address_space_rw(as, N90_DT_PA, MEMTXATTRS_UNSPECIFIED, data, size, 1);
    *dt_len = (uint32_t)size;
    info_report("n90ap: devicetree %zu bytes at pa 0x%08llx", (size_t)size,
                (unsigned long long)N90_DT_PA);
    g_free(data);
}

/* Stage a raw RAMDisk image (N90_RAMDISK env, e.g. an HFS+ volume) at the
 * physical address the injected DT /chosen/memory-map/RAMDisk reg claims.
 * xnu's bsd root-device probe matches md0 against this region; without it
 * the kernel spins in the "Still waiting for root device" state machine. */
static void n90_load_ramdisk(AddressSpace *as)
{
    const char *path = getenv("N90_RAMDISK");
    if (!path) {
        info_report("n90ap: no N90_RAMDISK, booting without a RAMDisk device");
        return;
    }
    uint8_t *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, (char **)&data, &size, NULL)) {
        error_report("n90ap: cannot read ramdisk '%s'", path);
        exit(1);
    }
    /* keep the whole image within RAM (0x40000000..0x60000000) */
    if (size > N90_RAM_SIZE - (N90_RAMDISK_PA - N90_RAM_BASE)) {
        error_report("n90ap: ramdisk %zu bytes does not fit at 0x%08llx",
                     (size_t)size, (unsigned long long)N90_RAMDISK_PA);
        exit(1);
    }
    address_space_rw(as, N90_RAMDISK_PA, MEMTXATTRS_UNSPECIFIED, data, size, 1);
    info_report("n90ap: ramdisk %zu bytes at pa 0x%08llx",
                (size_t)size, (unsigned long long)N90_RAMDISK_PA);
    g_free(data);
}

static void n90_write_bootargs(AddressSpace *as, uint32_t dt_len,
                               const char *cmdline)
{
    BootArgs ba;
    memset(&ba, 0, sizeof(ba));
    ba.Revision = 2;
    ba.Version = 2; /* patched from the machine 'epoch' property below */
    /* start.s maps VA[virtBase] -> PA[physBase] per 1MB section, for memSize
     * bytes, then converts r0 = args_pa - physBase + virtBase. */
    ba.virtBase = N90_KERNEL_VA & 0xFF800000ULL;   /* 0x80000000 */
    ba.physBase = N90_RAM_BASE;                    /* 0x40000000 */
    ba.memSize = N90_RAM_SIZE;                     /* 512 MB, signed-positive */
    ba.topOfKernelData = N90_TOPOFKERNEL;
    /* Real iBoot hands the kernel a live framebuffer; a zeroed Video block
     * pushes pexpert down the serial-console path. iPhone 4: 640x960 ARGB. */
    ba.video_v_base = 0x5F000000ULL;      /* inside DRAM, below bootargs */
    ba.video_v_display = 1;               /* kPEGraphicsMode */
    ba.video_v_rowBytes = 640 * 4;        /* 2560 */
    ba.video_v_width = 640;
    ba.video_v_height = 960;
    ba.video_v_depth = 32;
    ba.machineType = 0;
    ba.deviceTreeP = N90_DT_VA;   /* virtual; mapped by the boot PT */
    ba.deviceTreeLength = dt_len;
    g_strlcpy(ba.CommandLine, cmdline, BOOT_LINE_LENGTH);
    ba.bootFlags = 0;
    ba.memSizeActual = N90_RAM_SIZE;
    address_space_rw(as, N90_BOOTARGS_PA, MEMTXATTRS_UNSPECIFIED,
                     (uint8_t *)&ba, sizeof(ba), 1);
    info_report("n90ap: boot_args at pa 0x%08llx (cmdline '%s')",
                (unsigned long long)N90_BOOTARGS_PA, cmdline);
}

/* second pass so the epoch property (set after -M parsing) is honored */
static void n90_patch_bootargs_epoch(N90MachineState *s, AddressSpace *as)
{
    address_space_rw(as, N90_BOOTARGS_PA + 2, MEMTXATTRS_UNSPECIFIED,
                     (uint8_t *)&s->epoch, sizeof(s->epoch), 1);
    info_report("n90ap: boot_args Version = 0x%x", s->epoch);
}

/* Extend the boot page table start.s built (virtBase window + PC section +
 * high vectors) with the bus-alias mappings real iBoot provides: the kernel
 * early code touches VA 0xC0001000 (= PA 0x40001000 through the S5L8930
 * +0x80000000 bus alias, lowGlo / image page) before vm bootstrap installs
 * its own tables. */
#define N90_BOOT_PT_PA      N90_TOPOFKERNEL
#define N90_SECTION_ATTR    0x40EULL

static void n90_patch_bootpt(AddressSpace *as)
{
    uint32_t desc;
    /* VA 0xC0000000-0xDFFFFFFF -> PA 0x40000000-0x5FFFFFFF (RAM alias) */
    for (uint32_t i = 0xC00; i < 0xE00; i++) {
        desc = (uint32_t)(0x40000000ULL + ((i - 0xC00) << 20)) | N90_SECTION_ATTR;
        address_space_rw(as, N90_BOOT_PT_PA + i * 4, MEMTXATTRS_UNSPECIFIED,
                         (uint8_t *)&desc, 4, 1);
    }
    info_report("n90ap: boot PT extended: VA C0000000-C1FFFFFF -> RAM alias");
}

/* Early-boot workaround: the kernel's ml_at_interrupt_context (trap.c:501
 * consumer) classifies any data abort taken on the master boot stack as
 * "abort in interrupt context" and panics, because fleh runs kernel-mode
 * aborts on the interrupted thread's own stack and the bootstrap thread
 * still lives inside the IRQ-stack detection window.  That check blocks the
 * on-demand vm_fault path the kernel VA space relies on (kernel map starts
 * at 0xC0001000).  NOP the check so kernel data aborts reach vm_fault;
 * revisit once a dedicated IRQ stack is initialized. */
#define N90_ML_AT_INT_CTX_VA 0x8006c52cULL
static void n90_patch_ml_at_interrupt_context(AddressSpace *as)
{
    /* Thumb2: movs r0,#0 ; bx lr  ->  always "not in interrupt context" */
    static const uint8_t thunk[4] = { 0x00, 0x20, 0x70, 0x47 };
    hwaddr pa = N90_ML_AT_INT_CTX_VA - 0x40000000ULL;
    address_space_rw(as, pa, MEMTXATTRS_UNSPECIFIED, (uint8_t *)thunk, 4, 1);
    info_report("n90ap: patched ml_at_interrupt_context @ VA 0x8006c52c -> always false");
}

/* IOFindBSDRoot (bsd/dev/arm/IOFindBSDRoot.c) panics immediately when the
 * boot-uuid property path fails, instead of falling into the "Still waiting
 * for root device" retry loop.  The backtrace lands at VA 0x801fb185
 * (Thumb LR+1), i.e.  blx r3 at 0x801fb182 where r3 = [0x801fb2c4] = _panic.
 * There is a second candidate call site at 0x801fb124 (same literal).
 * NOP both 16-bit blx r3 (opcode 0x4798) so root probing falls through to
 * the 0x801fa9a8 retry loop and prints diagnostics instead of panicking. */
#define N90_IOFINDROOT_PANIC1 0x801fb182ULL
#define N90_IOFINDROOT_PANIC2 0x801fb124ULL
static void n90_patch_iofindroot_panic(AddressSpace *as)
{
    /* Thumb2 16-bit NOP = 0xBF00, stored little-endian */
    static const uint8_t nop16[2] = { 0x00, 0xbf };
    hwaddr pa1 = N90_IOFINDROOT_PANIC1 - 0x40000000ULL;
    hwaddr pa2 = N90_IOFINDROOT_PANIC2 - 0x40000000ULL;
    address_space_rw(as, pa1, MEMTXATTRS_UNSPECIFIED, (uint8_t *)nop16, 2, 1);
    address_space_rw(as, pa2, MEMTXATTRS_UNSPECIFIED, (uint8_t *)nop16, 2, 1);
    info_report("n90ap: patched IOFindBSDRoot panic sites 0x%08llx/0x%08llx -> NOP",
                (unsigned long long)N90_IOFINDROOT_PANIC1,
                (unsigned long long)N90_IOFINDROOT_PANIC2);
}

static void n90_cpu_reset(void *opaque)
{
    N90MachineState *s = N90_MACHINE((MachineState *)opaque);
    ARMCPU *cpu = s->cpu;
    CPUState *cs = CPU(cpu);

    cpu_reset(cs);
    /* start executing at the PHYSICAL entry with MMU off */
    cpu_set_pc(cs, s->kernel_entry - N90_VIRT_OFFSET);
    cpu->env.regs[0] = N90_BOOTARGS_PA;
}

/* S5L8930 tick timer: free-running 64-bit counter at PMGR + 0x2000
 * (phys 0x3F102000), 24 MHz (per winocm's uboot-iphone4 and Corellium's
 * xnu pexpert/arm/pe_s5l8930x.h: CLOCK_LOW +0x00, CLOCK_HIGH +0x04,
 * VAL +0x08, CTRL +0x10). */
#define N90_TICK_BASE   0x3F102000ULL
#define N90_TICK_HZ     24000000ULL

/* S5L8930 TIMER0: free-running 64-bit counter plus an IRQ enable (CTRL
 * bit0) and expired status (CTRL bit1).  Without a periodic tick the kernel
 * scheduler never wakes and blocks forever on its first mutex. */
typedef struct N90TickState {
    qemu_irq irq;
    QEMUTimer *timer;
    bool enabled;
    uint32_t ctrl;
} N90TickState;
static N90TickState g_n90_tick;

#define N90_TICK_PERIOD_NS (10ULL * 1000000ULL) /* 100 Hz */

/* Worth-Doing-Badly style scheduler kick: on real hardware iBoot leaves the
 * platform timer + FIQ running when the kernel starts, and xnu-1735 relies on
 * that FIQ for its first tick (it never programs our TIMER0 block).  Raise a
 * periodic FIQ directly on the CPU, independent of the VIC. */
static QEMUTimer *g_n90_fiq_timer;
static ARMCPU *g_n90_cpu;

static void n90_fiq_fire(void *opaque)
{
    /* Always kick: the guest enables vic0 line6 as FIQ but never gets any
     * interrupt through (RAWINTR bit6 stays 0), so its deadline waits
     * (assert_wait_deadline) never time out.  Keep an FIQ storm until the
     * guest's own FIQ handler starts consuming ticks. */
static int n90_kick_count;
    cpu_interrupt(CPU(g_n90_cpu), CPU_INTERRUPT_FIQ);
    /* Also raise IRQ: the guest runs with CPSR.I set (no IRQ exceptions ever
     * taken, per -d int trace) and blocks on IRQ-driven wait machinery.
     * The guest's own CPSR.I gates delivery, so this only helps. */
    cpu_interrupt(CPU(g_n90_cpu), CPU_INTERRUPT_HARD);
    if ((++n90_kick_count % 10) == 0) {
        CPUARMState *env = &g_n90_cpu->env;
        uint32_t pc = env->regs[15];

        /* boot-path probes: once each, report when the guest PC was seen
         * inside the kernel's root-finding / RAMDisk code while we are
         * storming it with FIQ.  Catches "never even reached" vs "reached
         * but stuck". */
        static int n90_probe_iof, n90_probe_roc, n90_probe_mdev,
                   n90_probe_rand, n90_probe_rand2;
        if (pc >= 0x801fa8c0u && pc < 0x801fb300u) {
            if (!n90_probe_iof) {
                n90_probe_iof = 1;
                fprintf(stderr, "probe: pc in IOFindBSDRoot 0x%08x lr=0x%08x\n",
                        pc, env->regs[14]);
            }
        }
        if (pc >= 0x801fac56u && pc < 0x801facba && !n90_probe_roc) {
            n90_probe_roc = 1;
            fprintf(stderr, "probe: pc in RAMDisk branch 0x%08x lr=0x%08x\n",
                    pc, env->regs[14]);
        }
        if ((pc >= 0x800782b0u && pc < 0x80078440u) && !n90_probe_mdev) {
            n90_probe_mdev = 1;
            fprintf(stderr, "probe: pc in mdevadd 0x%08x lr=0x%08x\n",
                    pc, env->regs[14]);
        }
        if (pc == 0x801fb182u && !n90_probe_rand) {
            n90_probe_rand = 1;
            fprintf(stderr, "probe: pc at panic1 0x801fb182 lr=0x%08x\n",
                    env->regs[14]);
        }
        if (pc == 0x801fb124u && !n90_probe_rand2) {
            n90_probe_rand2 = 1;
            fprintf(stderr, "probe: pc at panic2 0x801fb124 lr=0x%08x\n",
                    env->regs[14]);
        }
        uint32_t sp0 = env->regs[13];
        uint32_t w[8] = {0};
        hwaddr pa = sp0;
        if (sp0 >= 0xC0000000u) {
            pa = sp0 - 0x80000000u;
        } else if (sp0 >= 0x80000000u) {
            pa = sp0 - 0x40000000u;
        }
        if (pa >= 0x40000000u && pa + 32 <= 0x40000000u + N90_RAM_SIZE) {
            uint8_t buf[32];
            if (address_space_rw(&address_space_memory, pa, MEMTXATTRS_UNSPECIFIED,
                                 buf, 32, 0) == 0) {
                memcpy(w, buf, 32);
            }
        }
        /* wait object 0x802c0ea0 (VA) -> PA 0x402c0ea0: state @+0x8,
         * threadA @+0xc, waitq head @+0x18 (0x802bdc54); dump state +q. */
        uint32_t qwords[4] = {0};
        uint8_t qbuf[16];
        if (address_space_rw(&address_space_memory, 0x402c0ea0,
                             MEMTXATTRS_UNSPECIFIED, qbuf, 16, 0) == 0) {
            memcpy(qwords, qbuf, 16);
        }
        fprintf(stderr,
                "fiq_kick %d pc=0x%08x lr=0x%08x cpsr=%08x sp=0x%08x tpidr=0x%08x"
                " qst=%u qa=%08x qb=%08x"
                " stk=%08x %08x %08x %08x %08x %08x %08x %08x\n",
                n90_kick_count, pc, env->regs[14], env->pstate, sp0,
                env->cp15.tpidrprw_s,
                qwords[2], qwords[3], qwords[1],
                w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
    }

    /* Bypass: object 0x802c0ea0 (VA) boot-wait, state @+0x8 (PA 0x402c0ea8).
     * If its state word is still in a pre-3 transition (1/2), force it to 3
     * so the boot sequence unblocks.  States 4/5/6 are in-flight values we
     * must not clobber. */
    {   uint32_t st;
        uint8_t stb[4];
        if (address_space_rw(&address_space_memory, 0x402c0ea8,
                             MEMTXATTRS_UNSPECIFIED, stb, 4, 0) == 0) {
            memcpy(&st, stb, 4);
            if (st == 1 || st == 2) {
                st = 3;
                memcpy(stb, &st, 4);
                address_space_rw(&address_space_memory, 0x402c0ea8,
                                 MEMTXATTRS_UNSPECIFIED, stb, 4, 1);
            }
        }
    }
    timer_mod(g_n90_fiq_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + N90_TICK_PERIOD_NS);
}

static void n90_tick_fire(void *opaque)
{
    N90TickState *t = opaque;
    if (!t->enabled) {
        return;
    }
    t->ctrl |= 0x2;
    qemu_set_irq(t->irq, 1);
    fprintf(stderr, "tick_fire ctrl=%x\n", t->ctrl);
    timer_mod(t->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + N90_TICK_PERIOD_NS);
}

static uint32_t g_n90_read_count = 0;
static uint64_t n90_tick_read(void *opaque, hwaddr addr, unsigned size)
{
    uint64_t ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint64_t ticks = muldiv64(ns, N90_TICK_HZ, 1000000000ULL);
    switch (addr) {
    case 0x00: /* CLOCK_LOW */
    case 0x08: /* VAL */
        g_n90_read_count++;
        return (uint32_t)ticks;
    case 0x04: /* CLOCK_HIGH */
        return (uint32_t)(ticks >> 32);
    case 0x10: /* CTRL */
        return g_n90_tick.ctrl;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "n90: tick READ 0x%02llx\n",
                      (unsigned long long)addr);
        return 0;
    }
}

static void n90_tick_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    N90TickState *t = &g_n90_tick;
    switch (addr) {
    case 0x10: /* CTRL: bit0 irq enable, bit1 expired/ack */
        t->ctrl = (uint32_t)value & 0x3;
        t->enabled = value & 1;
        if (value & 1) {
            timer_mod(t->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + N90_TICK_PERIOD_NS);
        } else {
            timer_del(t->timer);
        }
        if (!(value & 1) || (value & 2)) {
            /* guest acked/cleared: drop the line */
            qemu_set_irq(t->irq, 0);
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "n90: tick WRITE 0x%02llx = 0x%llx\n",
                      (unsigned long long)addr, (unsigned long long)value);
        break;
    }
}

static const MemoryRegionOps n90_tick_ops = {
    .read = n90_tick_read,
    .write = n90_tick_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

/* Diagnostic (N90_STATTRAP=1): shadow the boot-wait object's state field
 * (kernel VA 0x802c0ea0+8 = PA 0x402c0ea8) with a small overlay region so
 * every write to it is logged with the writer's PC/LR.  Gives the identity
 * of the state machine that never leaves 4/6. */
#define N90_STATTRACE_PA 0x402c0ea8ULL
static MemoryRegion g_stattr_mr;
static uint8_t *g_stattr_backing;

static uint64_t n90_stattr_read(void *opaque, hwaddr offset, unsigned size)
{
    return ldl_p(g_stattr_backing);
}

static void n90_stattr_write(void *opaque, hwaddr offset, uint64_t val,
                             unsigned size)
{
    uint32_t pc = 0, lr = 0;
    if (current_cpu) {
        ARMCPU *acpu = ARM_CPU(current_cpu);
        pc = (uint32_t)acpu->env.regs[15];
        lr = (uint32_t)acpu->env.regs[14];
    }
    fprintf(stderr, "stattr <= 0x%x (pc=0x%08x lr=0x%08x)\n",
            (uint32_t)val, pc, lr);
    stl_p(g_stattr_backing, (uint32_t)val);
}

static const MemoryRegionOps n90_stattr_ops = {
    .read = n90_stattr_read,
    .write = n90_stattr_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static char *n90_get_kcache(Object *obj, Error **errp)
{
    return g_strdup(N90_MACHINE(obj)->kcache_path);
}
static void n90_set_kcache(Object *obj, const char *value, Error **errp)
{
    if (!g_file_test(value, G_FILE_TEST_EXISTS)) {
        error_report("n90ap: kernelcache '%s' must exist", value);
        exit(1);
    }
    g_strlcpy(N90_MACHINE(obj)->kcache_path, value, sizeof(N90_MACHINE(obj)->kcache_path));
}
static char *n90_get_dtree(Object *obj, Error **errp)
{
    return g_strdup(N90_MACHINE(obj)->dtree_path);
}
static void n90_set_dtree(Object *obj, const char *value, Error **errp)
{
    if (!g_file_test(value, G_FILE_TEST_EXISTS)) {
        error_report("n90ap: devicetree '%s' must exist", value);
        exit(1);
    }
    g_strlcpy(N90_MACHINE(obj)->dtree_path, value, sizeof(N90_MACHINE(obj)->dtree_path));
}
static char *n90_get_epoch(Object *obj, Error **errp)
{
    return g_strdup_printf("0x%x", N90_MACHINE(obj)->epoch);
}
static void n90_set_epoch(Object *obj, const char *value, Error **errp)
{
    N90MachineState *s = N90_MACHINE(obj);
    s->epoch = (uint16_t)strtoul(value, NULL, 0);
}

static char *n90_get_bootargs(Object *obj, Error **errp)
{
    N90MachineState *s = N90_MACHINE(obj);
    return g_strdup(s->bootargs ? s->bootargs : "");
}

static void n90_set_bootargs(Object *obj, const char *value, Error **errp)
{
    N90MachineState *s = N90_MACHINE(obj);
    g_free(s->bootargs);
    s->bootargs = g_strdup(value);
}

static void n90_instance_init(Object *obj)
{
    N90MachineState *s = N90_MACHINE(obj);
    /* xnu-1504 (iOS 4.x) era epoch; tune with -M n90ap,epoch=0xNN if the
     * kernel prints "pe_identify_machine: Epoch Mismatch" */
    s->epoch = 2;
    object_property_add_str(obj, "kcache", n90_get_kcache, n90_set_kcache);
    object_property_set_description(obj, "kcache", "Path to decrypted+decompressed kernelcache Mach-O");
    object_property_add_str(obj, "devicetree", n90_get_dtree, n90_set_dtree);
    object_property_set_description(obj, "devicetree", "Path to decrypted device tree blob");
    object_property_add_str(obj, "epoch", n90_get_epoch, n90_set_epoch);
    object_property_set_description(obj, "epoch", "boot_args Version (u16 at +2) the kernel expects");
    object_property_add_str(obj, "bootargs", n90_get_bootargs, n90_set_bootargs);
    object_property_set_description(obj, "bootargs", "boot_args CommandLine string (kern boot-args)");
}

static void n90_machine_init(MachineState *machine)
{
    N90MachineState *s = N90_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();
    AddressSpace *nsas;
    DeviceState *dev;
    uint32_t dt_len = 0;
    PL192State *vic[N90_NUM_VICS];

    /* CPU: single Cortex-A8 (A4) */
    Object *cpuobj = object_new(machine->cpu_type);
    s->cpu = ARM_CPU(cpuobj);
    object_property_set_link(cpuobj, "memory", OBJECT(sysmem), &error_abort);
    object_property_set_bool(cpuobj, "has_el3", false, NULL);
    object_property_set_bool(cpuobj, "has_el2", false, NULL);
    object_property_set_bool(cpuobj, "realized", true, &error_fatal);
    nsas = cpu_get_address_space(CPU(s->cpu), ARMASIdx_NS);
    define_arm_cp_regs(s->cpu, n90_cp_reginfo);
    object_unref(cpuobj);

    /* 512 MB DRAM at 0x40000000 */
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, NULL, "n90.ram", N90_RAM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, N90_RAM_BASE, ram);
    if (getenv("N90_STATTRAP")) {
        g_stattr_backing = memory_region_get_ram_ptr(ram) +
                           (N90_STATTRACE_PA - N90_RAM_BASE);
        memory_region_init_io(&g_stattr_mr, NULL, &n90_stattr_ops, NULL,
                              "n90.stattr", 4);
        memory_region_add_subregion(sysmem, N90_STATTRACE_PA, &g_stattr_mr);
        info_report("n90ap: state-field write trap @ PA 0x%08llx",
                    (unsigned long long)N90_STATTRACE_PA);
    }
    /* S5L8930 bus alias windows (confirmed by Corellium's pexpert header:
     * UART0 0x82500000, GPIO 0xBFA00000, TIMER 0xBF102000 = PA + 0x80000000):
     *   0x80000000-0xBFFFFFFF aliases peripherals (0x00000000-0x3FFFFFFF)
     *   0xC0000000-0xFFFFFFFF aliases DRAM        (0x40000000-0x7FFFFFFF)
     * The kernel's MANAGED_BASE 0xC0000000 thus lands on PA 0x40000000. */
    MemoryRegion *alias_periph = g_new(MemoryRegion, 1);
    memory_region_init_alias(alias_periph, NULL, "n90.alias-periph",
                             get_system_memory(), 0x0ULL, 0x40000000ULL);
    memory_region_add_subregion(sysmem, 0x80000000ULL, alias_periph);
    MemoryRegion *alias_ram = g_new(MemoryRegion, 1);
    memory_region_init_alias(alias_ram, NULL, "n90.alias-ram",
                             get_system_memory(), N90_RAM_BASE, 0x40000000ULL);
    memory_region_add_subregion(sysmem, 0xC0000000ULL, alias_ram);

    /* 4x PL192 VIC at 0x3F200000, stride 0x10000; vic0 drives the CPU,
     * vic1..3 cascade through the daisy chain (like devos50's setup). */
    for (int i = 0; i < N90_NUM_VICS; i++) {
        dev = pl192_manual_init(g_strdup_printf("n90.vic%d", i),
                                i == 0 ? qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_IRQ) : NULL,
                                i == 0 ? qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_FIQ) : NULL,
                                NULL);
        vic[i] = PL192(dev);
        memory_region_add_subregion(sysmem, N90_VIC_BASE + i * N90_VIC_STRIDE,
                                    &vic[i]->iomem);
        if (i > 0) {
            vic[i]->daisy = vic[0];
        }
        for (int j = 0; j < N90_IRQS_PER_VIC; j++) {
            s->irq[i * N90_IRQS_PER_VIC + j] = qdev_get_gpio_in(dev, j);
        }
    }

    /* UART0-5 (samsung layout, exynos4210 model) */
    for (int i = 0; i < 6; i++) {
        qemu_irq irq = s->irq[n90_uart_irq[i]];
        dev = exynos4210_uart_create(n90_uart_base[i], 256, i,
                                     i == 0 ? serial_hd(0) : NULL, irq);
        if (!dev) {
            error_report("n90ap: failed to create UART%d", i);
            exit(1);
        }
    }

    /* Tick timer (free-running 24 MHz counter) at PMGR + 0x2000 */
    MemoryRegion *tick = g_new(MemoryRegion, 1);
    /* The kernel enables vic0 line 6 as FIQ for its platform timer tick
     * (nothing else in the DT claims irq 6; observed live in INT_SELECT/
     * INT_ENABLE = 0x40). Our tick device must drive that line, not the
     * cpu0 "interrupts" property value. */
    g_n90_tick.irq = s->irq[6];
    g_n90_tick.timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, n90_tick_fire, &g_n90_tick);
    memory_region_init_io(tick, NULL, &n90_tick_ops, s, "n90.tick", 0x100);
    memory_region_add_subregion(sysmem, N90_TICK_BASE, tick);

    /* Periodic FIQ kick (masked by the guest's CPSR.F until it is ready) */
    g_n90_cpu = s->cpu;
    g_n90_fiq_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, n90_fiq_fire, NULL);
    timer_mod(g_n90_fiq_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + N90_TICK_PERIOD_NS);

    /* PMGR windows; the 0x2000 page is covered by the tick timer above */
    create_unimplemented_device("n90.pmgr",    N90_PMGR_BASE, 0x2000);
    create_unimplemented_device("n90.pmgrb",   N90_PMGR_BASE + 0x2100, N90_PMGR_SIZE - 0x2100);
    create_unimplemented_device("n90.pmgr2",   0x5E00000, 0x1000);
    create_unimplemented_device("n90.pmgr3",   0x5F00000, 0x1000);
    create_unimplemented_device("n90.pmgr4",   0x8E00000, 0x1000);
    create_unimplemented_device("n90.pmgr5",   0x8F00000, 0x1000);
    create_unimplemented_device("n90.pmgr6",   0x9E00000, 0x1000);
    create_unimplemented_device("n90.pmgr7",   0x9F00000, 0x1000);
    create_unimplemented_device("n90.gpio",    0x3FA00000, 0x1000);
    create_unimplemented_device("n90.armio",   0xBFC00000, 0x1000);
    create_unimplemented_device("n90.cpudev",  0x3F700000, 0x2000);
    create_unimplemented_device("n90.iws",     0x3F600000, 0x1000);
    create_unimplemented_device("n90.fmi",     0x1200000, 0x10000);
    create_unimplemented_device("n90.sha1",    0x1000000, 0x1000);
    create_unimplemented_device("n90.aes",     0x1C00000, 0x1000);
    create_unimplemented_device("n90.spi0",    0x2000000, 0x1000);
    create_unimplemented_device("n90.spi1",    0x2100000, 0x1000);
    create_unimplemented_device("n90.spi2",    0x2200000, 0x1000);
    create_unimplemented_device("n90.kepler",  0x3100000, 0x1000);
    create_unimplemented_device("n90.i2c0",    0x3200000, 0x1000);
    create_unimplemented_device("n90.i2c2",    0x3400000, 0x1000);
    create_unimplemented_device("n90.pwm",     0x3500000, 0x1000);
    create_unimplemented_device("n90.dmac",    0x4100000, 0x3000);
    create_unimplemented_device("n90.dmac2",   0x4000000, 0x40000);
    create_unimplemented_device("n90.dmac3",   0x4300000, 0x5000);
    /* DT arm-io/cdma: S5L8930 CDMA controller, two register windows. The
     * S5L8930X driver maps both and writes irq registers in it during start. */
    create_unimplemented_device("n90.cdma",    0x7000000, 0x26000);
    create_unimplemented_device("n90.cdma2",   0x7800000, 0x9000);
    /* Community s5l8930.h map: I2C1 0x83300000, SPI3/4 0x823/0x82400000,
     * H2FMI1 0x81300000, CHIPID 0xBF500000. */
    create_unimplemented_device("n90.i2c1",    0x3300000, 0x1000);
    create_unimplemented_device("n90.spi3",    0x2300000, 0x1000);
    create_unimplemented_device("n90.spi4",    0x2400000, 0x1000);
    create_unimplemented_device("n90.fmi1",    0x1300000, 0x10000);
    create_unimplemented_device("n90.chipid",  0x3F500000, 0x1000);
    create_unimplemented_device("n90.i2s0",    0x4500400, 0xC00);
    create_unimplemented_device("n90.i2s1",    0x4501400, 0xC00);
    create_unimplemented_device("n90.i2s2",    0x4502400, 0xC00);
    create_unimplemented_device("n90.otgphy",  0x6000000, 0x1000);
    create_unimplemented_device("n90.usbcplx", 0x6100000, 0x600000);
    create_unimplemented_device("n90.iop",     0x6300000, 0x1000);
    create_unimplemented_device("n90.vxd",     0x5000000, 0x100000);
    create_unimplemented_device("n90.sgx",     0x5100000, 0x1000);
    create_unimplemented_device("n90.venc",    0x8000000, 0x1000);
    create_unimplemented_device("n90.isp",     0x8300000, 0xD6000);
    create_unimplemented_device("n90.isp2",    0x8100000, 0x1000);
    create_unimplemented_device("n90.dart0",   0x8D00000, 0x2000);
    create_unimplemented_device("n90.dart1",   0x9D00000, 0x2000);
    create_unimplemented_device("n90.dsi",     0x9000000, 0x7000);
    create_unimplemented_device("n90.dsi2",    0x9200000, 0x2000);
    create_unimplemented_device("n90.rgbout",  0x9100000, 0x7000);
    create_unimplemented_device("n90.rgbout2", 0x9600000, 0x1000);
    create_unimplemented_device("n90.scaler",  0x9300000, 0x1000);
    create_unimplemented_device("n90.tvout",   0x9400000, 0x1000);
    create_unimplemented_device("n90.mipi",    0x9500000, 0x1000);

    n90_load_kernel(s, nsas);
    n90_load_dtree(s, nsas, &dt_len);
    n90_load_ramdisk(nsas);
    n90_write_bootargs(nsas, dt_len,
                       s->bootargs ? s->bootargs
                       : (machine->kernel_cmdline ? machine->kernel_cmdline : ""));
    n90_patch_bootargs_epoch(s, nsas);
    n90_patch_bootpt(nsas);
    n90_patch_ml_at_interrupt_context(nsas);
    n90_patch_iofindroot_panic(nsas);

    qemu_register_reset(n90_cpu_reset, s);
}

static void n90_machine_class_init(ObjectClass *klass, void *data)
{
    MachineClass *mc = MACHINE_CLASS(klass);
    mc->desc = "iPhone 3,1 N90AP (S5L8930X A4) - direct kernel boot";
    mc->init = n90_machine_init;
    mc->max_cpus = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a8");
    mc->default_ram_id = NULL;
}

static const TypeInfo n90_machine_info = {
    .name          = TYPE_N90_MACHINE,
    .parent        = TYPE_MACHINE,
    .instance_size = sizeof(N90MachineState),
    .class_init    = n90_machine_class_init,
    .instance_init = n90_instance_init,
};

static void n90_machine_types(void)
{
    type_register_static(&n90_machine_info);
}
type_init(n90_machine_types)
