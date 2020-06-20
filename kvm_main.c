/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/debugfs.h>

#include <asm-bs/msr.h>
#include "kvm.h"

struct kvm_stat_bs kvm_stat_bs;
EXPORT_SYMBOL_GPL(kvm_stat_bs);

static struct kvm_stats_debugfs_item_bs {
	const char *name;
	u32 *data;
	struct dentry *dentry;
} debugfs_entries_bs[] = {
	{ "pf_fixed", &kvm_stat_bs.pf_fixed },
	{ "pf_guest", &kvm_stat_bs.pf_guest },
	{ "tlb_flush", &kvm_stat_bs.tlb_flush },
	{ "invlpg", &kvm_stat_bs.invlpg },
	{ "exits", &kvm_stat_bs.exits },
	{ "io_exits", &kvm_stat_bs.io_exits },
	{ "mmio_exits", &kvm_stat_bs.mmio_exits },
	{ "signal_exits", &kvm_stat_bs.signal_exits },
	{ "irq_window", &kvm_stat_bs.irq_window_exits },
	{ "halt_exits", &kvm_stat_bs.halt_exits },
	{ "request_irq", &kvm_stat_bs.request_irq_exits },
	{ "irq_exits", &kvm_stat_bs.irq_exits },
	{ 0, 0 }
};

static struct dentry *debugfs_dir_bs;
hpa_t_bs bad_page_address_bs;

/*
 * List of msr numbers which we expose to userspace through KVM_GET_MSRS
 * and KVM_SET_MSRS, and KVM_GET_MSR_INDEX_LIST.
 *
 * This list is modified at module load time to reflect the
 * capabilities of the host cpu.
 */
static u32 msrs_to_save_bs[] = {
	MSR_IA32_SYSENTER_CS_BS,
	MSR_IA32_SYSENTER_ESP_BS,
	MSR_IA32_SYSENTER_EIP_BS,
	MSR_K6_STAR_BS,
	MSR_IA32_TIME_STAMP_COUNTER_BS,
};

static unsigned num_msrs_to_save_bs;

static __init void kvm_init_debug_bs(void)
{
	struct kvm_stats_debugfs_item_bs *p;

	debugfs_dir_bs = debugfs_create_dir("kvm_bs", 0);
	for (p = debugfs_entries_bs; p->name; ++p)
		p->dentry = debugfs_create_u32(p->name, 0444, debugfs_dir_bs,
						p->data);
}

static void kvm_exit_debug_bs(void)
{
	struct kvm_stats_debugfs_item_bs *p;

	for (p = debugfs_entries_bs; p->name; ++p)
		debugfs_remove(p->dentry);
	debugfs_remove(debugfs_dir_bs);
}

static __init void kvm_init_msr_list_bs(void)
{
	u32 dummy[2];
	unsigned i, j;

	for (i = j = 0; i < ARRAY_SIZE(msrs_to_save_bs); i++) {
		if (rdmsr_safe_bs(msrs_to_save_bs[i], 
						&dummy[0], &dummy[1]) < 0)
			continue;
		if (j < i)
			msrs_to_save_bs[j] = msrs_to_save_bs[i];
		j++;
	}
	num_msrs_to_save_bs = j;
}

static __init int kvm_init_bs(void)
{
	static struct page *bad_page;
	int r = 0;

	kvm_init_debug_bs();

	kvm_init_msr_list_bs();

	if ((bad_page = alloc_page(GFP_KERNEL)) == NULL) {
		r = -ENOMEM;
		goto out;
	}

	bad_page_address_bs = page_to_pfn(bad_page) << PAGE_SHIFT;
	memset(__va(bad_page_address_bs), 0, PAGE_SIZE);

	printk("KVM Module Init-stage.\n");
	return r;

out:
	kvm_exit_debug_bs();
	return r;
}

static __exit void kvm_exit_bs(void)
{
	struct kvm_stats_debugfs_item_bs *p;

	for (p = debugfs_entries_bs; p->name; p++)
		debugfs_remove(p->dentry);
	debugfs_remove(debugfs_dir_bs);
}

module_init(kvm_init_bs);
module_exit(kvm_exit_bs);

int kvm_init_arch_bs(struct kvm_arch_ops_bs *ops, struct module *module)
{
	return 0;
}

MODULE_AUTHOR("BiscuitOS Copy");
MODULE_LICENSE("GPL");
