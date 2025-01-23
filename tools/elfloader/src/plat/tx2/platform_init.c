/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/gen_config.h>
#include <elfloader.h>
#include <printf.h>

/* The code for enabling SError is from L4T (Linux for Tegra).
 * Read the Parker TRM 17.12 and 17.13 for NVIDIA-specific
 * SError extensions and the ARI (abstract request interface).
 */


#define SMC_SIP_INVOKE_MCE      0xc2ffff00
#define MCE_SMC_ENUM_MAX        0xff
#define ARI_MCA_GLOBAL_CONFIG   0x12
#define ARI_MCA_WRITE_SERR      0x2
#define NR_SMC_REGS             6

typedef union {
    struct {
        uint8_t cmd;
        uint8_t subidx;
        uint8_t idx;
        uint8_t inst;
    };
    struct {
        uint32_t low;
        uint32_t high;
    };
    uint64_t data;
} mca_cmd_t;

struct mce_regs {
    uint64_t args[NR_SMC_REGS];
};

static __attribute__((noinline)) int send_smc(uint8_t func, struct mce_regs *regs)
{
    uint32_t ret = SMC_SIP_INVOKE_MCE | (func & MCE_SMC_ENUM_MAX);
    asm volatile(
        "mov    x0, %x0\n"
        "ldp    x1, x2, [%1, #16 * 0] \n"
        "ldp    x3, x4, [%1, #16 * 1] \n"
        "ldp    x5, x6, [%1, #16 * 2] \n"
        "isb\n"
        "smc #0\n"
        "mov %x0, x0\n"
        "stp x0, x1, [%1, #16 * 0]\n"
        "stp x2, x3, [%1, #16 * 1]\n"
        : "+r"(ret)
        : "r"(regs)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
        "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17");
    return ret;
}


static void tegra_mce_write_uncore_mca(mca_cmd_t cmd, uint64_t data, uint32_t *err)
{
    struct mce_regs regs = {0};
    regs.args[0] = cmd.data;
    regs.args[1] = data;
    send_smc(13, &regs);
    *err = (uint32_t)regs.args[3];
}

static void enable_serr(void)
{
    uint32_t err;
    mca_cmd_t cmd;
    cmd.data = 0;
    cmd.cmd = ARI_MCA_WRITE_SERR;
    cmd.idx = ARI_MCA_GLOBAL_CONFIG;
    tegra_mce_write_uncore_mca(cmd, 1, &err);
    printf("Enabling TX2 SError result %d\n", err);
}

/* Enable SError report for TX2 */
void platform_init(void)
{
    enable_serr();
}
