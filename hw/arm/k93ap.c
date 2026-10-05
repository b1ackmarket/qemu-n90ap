/*
 * iPad 2,1 (k93ap / S5L8940X "A5") minimal machine model.
 *
 * Boots the XNU kernelcache directly by emulating the state iBoot leaves
 * behind: kernel mapped at 0x80001000, flattened device tree at 0x8F000000,
 * boot_args at 0x8FF00000, r0 = &boot_args, pc = kernel entry point taken
 * from LC_UNIXTHREAD.
 *
 * Usage:
 *   qemu-system-arm -M iPad2,1,kcache=kernelcache.bin,devicetree=devicetree.bin
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/misc/unimp.h"
#include "hw/irq.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "hw/qdev-clock.h"
#include "qemu/error-report.h"
#include "hw/boards.h"
#include "target/arm/cpu.h"
#include "hw/arm/exynos4210.h"

/* A5/iPad2,1: DRAM physical base is 0x00000000 (512 MB). The kernelcache is
 * VIRTUALLY linked at 0x80001000; bootargs[+4]=virtBase=0x80000000,
 * bootargs[+8]=physBase=0x0. start.s fills the boot PT: VA 0x80000000-0x9FFFFFFF
 * -> PA 0x0-0x1FFFFFFF, plus PC section identity. The kernel's own VM region
 * (VM_MIN_KERNEL_ADDRESS = 0xC0000000) aliases PA 0x40000000+. */
#define K93_RAM_BASE        0x40000000ULL
#define K93_RAM_SIZE        0x80000000ULL   /* 2 GB: VA window 0x80-0xFF -> PA 0x40-0xBF */
#define K93_VIRT_OFFSET     0x40000000ULL   /* va = pa + 0x40000000 (gVirtBase) */
#define K93_KERNEL_VA       0x80001000ULL
#define K93_KERNEL_PA       (K93_KERNEL_VA - K93_VIRT_OFFSET)
#define K93_DT_VA           0x8F000000ULL
#define K93_DT_PA           (K93_DT_VA - K93_VIRT_OFFSET)
#define K93_BOOTARGS_PA     0x4FF01000ULL
#define K93_TOPOFKERNEL     0x40DA0000ULL   /* phys, just above __PRELINK_INFO */

/* boot_args (pexpert/pexpert/arm/boot.h), version 2 */
#define BOOT_LINE_LENGTH    256
typedef struct BootArgs {
    uint16_t Revision;
    uint16_t Version;
    uint32_t virtBase;
    uint32_t physBase;
    uint32_t memSize;
    uint32_t topOfKernelData;
    /* Boot_Video */
    uint32_t video_v_base;
    uint32_t video_v_display;
    uint32_t video_v_width;
    uint32_t video_v_height;
    uint32_t video_v_depth;
    uint32_t video_v_rowBytes;
    uint32_t machineType;
    uint32_t deviceTreeP;
    uint32_t deviceTreeLength;
    char CommandLine[BOOT_LINE_LENGTH];
    uint32_t bootFlags;
    uint32_t memSizeActual;
} QEMU_PACKED BootArgs;

typedef struct K93MachineState {
    MachineState parent;
    char kcache_path[512];
    char dtree_path[512];
    ARMCPU *cpu;
    uint64_t kernel_entry;
} K93MachineState;

#define TYPE_K93_MACHINE MACHINE_TYPE_NAME("k93ap")
OBJECT_DECLARE_SIMPLE_TYPE(K93MachineState, K93_MACHINE);

static uint64_t kernel_entry_from_macho(const uint8_t *data, size_t size)
{
    uint32_t magic, ncmds;
    if (size < 32) return 0;
    magic = ldl_le_p(data);
    if (magic != 0xfeedface) { /* MH_MAGIC */
        error_report("k93ap: kernel is not a 32-bit LE Mach-O (magic %08x)", magic);
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

static void k93_load_kernel(K93MachineState *s, AddressSpace *as)
{
    uint8_t *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(s->kcache_path, (char **)&data, &size, NULL)) {
        error_report("k93ap: cannot read kernelcache '%s'", s->kcache_path);
        exit(1);
    }
    if (size > K93_RAM_SIZE) {
        error_report("k93ap: kernelcache too large: %zu", (size_t)size);
        exit(1);
    }
    s->kernel_entry = kernel_entry_from_macho(data, size);
    if (!s->kernel_entry) {
        error_report("k93ap: no LC_UNIXTHREAD entry point found");
        exit(1);
    }
    /* Load segments properly: copy file bytes to vmaddr, leave BSS (vmsize >
     * filesize) as zeroes. A raw file copy would splatter __LINKEDIT over
     * __bss/__common and corrupt every zero-init global. */
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
            uint64_t pa = vmaddr - K93_VIRT_OFFSET;
            if (fileoff + filesize <= size && pa >= K93_RAM_BASE &&
                pa + vmsize <= K93_RAM_BASE + K93_RAM_SIZE) {
                address_space_rw(as, pa, MEMTXATTRS_UNSPECIFIED,
                                 data + fileoff, filesize, 1);
                loaded += filesize;
            }
        }
        off += cmdsize;
    }
    info_report("k93ap: kernel %zu bytes, segments loaded %llu bytes, entry 0x%08llx",
                (size_t)size, (unsigned long long)loaded,
                (unsigned long long)s->kernel_entry);
    g_free(data);
}

static void k93_load_dtree(K93MachineState *s, AddressSpace *as, uint32_t *dt_len)
{
    uint8_t *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(s->dtree_path, (char **)&data, &size, NULL)) {
        error_report("k93ap: cannot read devicetree '%s'", s->dtree_path);
        exit(1);
    }
    address_space_rw(as, K93_DT_PA, MEMTXATTRS_UNSPECIFIED, data, size, 1);
    *dt_len = (uint32_t)size;
    info_report("k93ap: devicetree %zu bytes at pa 0x%08llx", (size_t)size,
                (unsigned long long)K93_DT_PA);
    g_free(data);
}

static void k93_write_bootargs(AddressSpace *as, uint32_t dt_len,
                               const char *cmdline)
{
    BootArgs ba;
    memset(&ba, 0, sizeof(ba));
    ba.Revision = 2;
    ba.Version = 0x12;   /* k93 kernel checks u16 at +2 == 0x12 ("Epoch") */
    /* [+4] = virtBase (kernel VM base for pmap alias), [+8] = physBase.
     * start.s maps VA[+4] -> PA[+8] (+ PC section identity) in the boot PT. */
    ba.virtBase = 0x80000000ULL;                  /* kernel VA window base */
    ba.physBase = 0x80000000ULL;                  /* fill maps VA 0xC0 -> PA 0x80 */
    ba.memSize = 0x20000000ULL;   /* 512 MB DRAM */
    ba.topOfKernelData = K93_TOPOFKERNEL;
    ba.machineType = 0;
    ba.deviceTreeP = K93_DT_VA;   /* virtual; kernel maps via boot PT */
    ba.deviceTreeLength = dt_len;
    g_strlcpy(ba.CommandLine, cmdline, BOOT_LINE_LENGTH);
    ba.bootFlags = 0;
    ba.memSizeActual = 0x20000000ULL;
    address_space_rw(as, K93_BOOTARGS_PA, MEMTXATTRS_UNSPECIFIED,
                     (uint8_t *)&ba, sizeof(ba), 1);
    info_report("k93ap: boot_args at pa 0x%08llx (cmdline '%s')",
                (unsigned long long)K93_BOOTARGS_PA, cmdline);
}

static void k93_cpu_reset(void *opaque)
{
    K93MachineState *s = K93_MACHINE((MachineState *)opaque);
    ARMCPU *cpu = s->cpu;
    CPUState *cs = CPU(cpu);

    cpu_reset(cs);
    /* start executing at the PHYSICAL entry with MMU off */
    cpu_set_pc(cs, s->kernel_entry - K93_VIRT_OFFSET);
    cpu->env.regs[0] = K93_BOOTARGS_PA;
}

static char *k93_get_kcache(Object *obj, Error **errp)
{
    return g_strdup(K93_MACHINE(obj)->kcache_path);
}
static void k93_set_kcache(Object *obj, const char *value, Error **errp)
{
    if (!g_file_test(value, G_FILE_TEST_EXISTS)) {
        error_report("k93ap: kernelcache '%s' must exist", value);
        exit(1);
    }
    g_strlcpy(K93_MACHINE(obj)->kcache_path, value, sizeof(K93_MACHINE(obj)->kcache_path));
}
static char *k93_get_dtree(Object *obj, Error **errp)
{
    return g_strdup(K93_MACHINE(obj)->dtree_path);
}
static void k93_set_dtree(Object *obj, const char *value, Error **errp)
{
    if (!g_file_test(value, G_FILE_TEST_EXISTS)) {
        error_report("k93ap: devicetree '%s' must exist", value);
        exit(1);
    }
    g_strlcpy(K93_MACHINE(obj)->dtree_path, value, sizeof(K93_MACHINE(obj)->dtree_path));
}

static void k93_instance_init(Object *obj)
{
    object_property_add_str(obj, "kcache", k93_get_kcache, k93_set_kcache);
    object_property_set_description(obj, "kcache", "Path to decrypted+decompressed kernelcache Mach-O");
    object_property_add_str(obj, "devicetree", k93_get_dtree, k93_set_dtree);
    object_property_set_description(obj, "devicetree", "Path to decrypted device tree blob");
}

static void k93_irq_nop(void *opaque, int n, int level) {}

static qemu_irq k93_irq_sink(void)
{
    return qemu_allocate_irq(k93_irq_nop, NULL, 0);
}

static void k93_machine_init(MachineState *machine)
{
    K93MachineState *s = K93_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();
    AddressSpace *nsas;
    DeviceState *dev;
    uint32_t dt_len = 0;

    /* CPU: single cortex-a9 to start (A5 has two; bring up cpu1 later) */
    Object *cpuobj = object_new(machine->cpu_type);
    s->cpu = ARM_CPU(cpuobj);
    object_property_set_link(cpuobj, "memory", OBJECT(sysmem), &error_abort);
    object_property_set_bool(cpuobj, "has_el3", false, NULL);
    object_property_set_bool(cpuobj, "has_el2", false, NULL);
    object_property_set_bool(cpuobj, "realized", true, &error_fatal);
    nsas = cpu_get_address_space(CPU(s->cpu), ARMASIdx_NS);
    object_unref(cpuobj);

    /* 512 MB DRAM at 0x80000000 */
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, NULL, "k93.ram", K93_RAM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, K93_RAM_BASE, ram);

    /* UART0 @ 0x2500000 (samsung uart-1 = exynos-style register layout) */
    dev = exynos4210_uart_create(0x2500000, 256, 0, serial_hd(0), k93_irq_sink());
    if (!dev) {
        error_report("k93ap: failed to create UART0");
        exit(1);
    }
    /* UART3 @ 0x2800000, UART5 @ 0x2A00000 (bluetooth / gas gauge, no chr) */
    exynos4210_uart_create(0x2800000, 256, 3, NULL, k93_irq_sink());
    exynos4210_uart_create(0x2A00000, 256, 5, NULL, k93_irq_sink());

    /* Unimplemented peripheral stubs from the k93ap device tree.
     * Reads return 0, writes ignored, and QEMU logs the accesses
     * (enable with -d unimp) so we can see what the kernel probes. */
    create_unimplemented_device("k93.aic",     0x0F200000, 0x10000);
    create_unimplemented_device("k93.pmgr",    0x0F100000, 0x7000);
    create_unimplemented_device("k93.pmgr2",   0x08C00000, 0x1000);
    create_unimplemented_device("k93.pmgr3",   0x08D00000, 0x1000);
    create_unimplemented_device("k93.pmgr4",   0x08E00000, 0x1000);
    create_unimplemented_device("k93.pmgr5",   0x08F00000, 0x1000);
    create_unimplemented_device("k93.pmgr6",   0x0A500000, 0x1000);
    create_unimplemented_device("k93.pmgr7",   0x0A600000, 0x1000);
    create_unimplemented_device("k93.wdt",     0x0F103020, 0x10);
    create_unimplemented_device("k93.gpio",    0x0FA00000, 0x1000);
    create_unimplemented_device("k93.armio",   0x3FB00000, 0x200000);
    create_unimplemented_device("k93.i2c0",    0x3200000, 0x1000);
    create_unimplemented_device("k93.i2c1",    0x3300000, 0x1000);
    create_unimplemented_device("k93.i2c2",    0x3400000, 0x1000);
    create_unimplemented_device("k93.fmi",     0x1200000, 0x190000);
    create_unimplemented_device("k93.spi1",    0x2100000, 0x1000);
    create_unimplemented_device("k93.sha2",    0x2000000, 0x1000);
    create_unimplemented_device("k93.pke",     0x3100000, 0x1000);
    create_unimplemented_device("k93.cdma",    0x7000000, 0x2d000);
    create_unimplemented_device("k93.cdma2",   0x7800000, 0x9000);
    create_unimplemented_device("k93.otgphy",  0x6000000, 0x1000);
    create_unimplemented_device("k93.ehci",    0x300000, 0x10000);
    create_unimplemented_device("k93.ohci0",   0x400000, 0x10000);
    create_unimplemented_device("k93.ohci1",   0x500000, 0x10000);
    create_unimplemented_device("k93.usbcplx", 0xF108000, 0x1000);
    create_unimplemented_device("k93.clcd",    0xA100000, 0x7000);
    create_unimplemented_device("k93.clcd2",   0x9200000, 0x2000);
    create_unimplemented_device("k93.clcd3",   0x9300000, 0x1000);
    create_unimplemented_device("k93.mipi",    0x9500000, 0x1000);
    create_unimplemented_device("k93.mipiclk", 0xF110000, 0x1000);
    create_unimplemented_device("k93.rgbout",  0xA200000, 0x7000);
    create_unimplemented_device("k93.rgbout2", 0x9600000, 0x1000);
    create_unimplemented_device("k93.tvout",   0x9400000, 0x1000);
    create_unimplemented_device("k93.dport",   0x9700000, 0x2000);
    create_unimplemented_device("k93.sgx",     0x5100000, 0x18000);
    create_unimplemented_device("k93.sgxclk",  0xF10B000, 0x1000);
    create_unimplemented_device("k93.dartnrt", 0x8B00000, 0x2000);
    create_unimplemented_device("k93.dartrt",  0xA400000, 0x2000);
    create_unimplemented_device("k93.scaler",  0x8300000, 0x2000);
    create_unimplemented_device("k93.jpeg",    0x8200000, 0x1000);
    create_unimplemented_device("k93.vxe",     0x8000000, 0x100000);
    create_unimplemented_device("k93.vxd",     0x8100000, 0x100000);
    create_unimplemented_device("k93.isp",     0xA000000, 0x100000);
    create_unimplemented_device("k93.iop",     0xF300000, 0x1000);
    create_unimplemented_device("k93.dwi",     0xF700000, 0x1000);
    create_unimplemented_device("k93.perf",    0xF104000, 0x1000);
    create_unimplemented_device("k93.perf2",   0xF800000, 0x1000);
    create_unimplemented_device("k93.trace",   0xD200000, 0x40000);
    create_unimplemented_device("k93.hpark",   0xB000000, 0x30000);
    create_unimplemented_device("k93.ae2",     0x4000000, 0x30000);
    create_unimplemented_device("k93.i2s",     0x4190000, 0x4000);
    create_unimplemented_device("k93.pl310",   0xE000000, 0x1000);
    create_unimplemented_device("k93.pl310w",  0xFD00000, 0x2000);

    k93_load_kernel(s, nsas);
    k93_load_dtree(s, nsas, &dt_len);
    k93_write_bootargs(nsas, dt_len, machine->kernel_cmdline ? machine->kernel_cmdline : "-v");

    qemu_register_reset(k93_cpu_reset, s);
}

static void k93_machine_class_init(ObjectClass *klass, void *data)
{
    MachineClass *mc = MACHINE_CLASS(klass);
    mc->desc = "iPad 2,1 (S5L8940X A5) - direct kernel boot";
    mc->init = k93_machine_init;
    mc->max_cpus = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a9");
    mc->default_ram_id = NULL;
}

static const TypeInfo k93_machine_info = {
    .name          = TYPE_K93_MACHINE,
    .parent        = TYPE_MACHINE,
    .instance_size = sizeof(K93MachineState),
    .class_init    = k93_machine_class_init,
    .instance_init = k93_instance_init,
};

static void k93_machine_types(void)
{
    type_register_static(&k93_machine_info);
}
type_init(k93_machine_types)
