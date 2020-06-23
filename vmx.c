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

#include <asm-bs/system.h>
#include "kvm.h"
#include "vmx.h"

static DEFINE_PER_CPU(struct vmcs_bs *, vmxarea_bs);

static struct vmcs_descriptor_bs {
	int size;
	int order;
	u32 revision_id;
} vmcs_descriptor_bs;

static __init int cpu_has_kvm_support_bs(void)
{
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}

/* 2-6.2 */
static __init int vmx_disabled_by_bios_bs(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL_BS, msr);
	return (msr & 5) == 1; /* locked but not enabled */
}

/* 3-A.1 */
static __init void setup_vmcs_descriptor_bs(void)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(MSR_IA32_VMX_BASIC_BS, vmx_msr_low, vmx_msr_high);
	vmcs_descriptor_bs.size = vmx_msr_high & 0x1fff;
	vmcs_descriptor_bs.order = get_order(vmcs_descriptor_bs.size);
	vmcs_descriptor_bs.revision_id = vmx_msr_low;
}

static struct vmcs_bs *alloc_vmcs_cpu_bs(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs_bs *vmcs;

	pages = alloc_pages_node(node, GFP_KERNEL, vmcs_descriptor_bs.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_descriptor_bs.size);
	vmcs->revision_id = vmcs_descriptor_bs.revision_id;
	return vmcs;
}

static void free_vmcs_bs(struct vmcs_bs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_descriptor_bs.order);
}

static __exit void free_kvm_area_bs(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		free_vmcs_bs(per_cpu(vmxarea_bs, cpu));
}

static __init int alloc_kvm_area_bs(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct vmcs_bs *vmcs;

		vmcs = alloc_vmcs_cpu_bs(cpu);
		if (!vmcs) {
			free_kvm_area_bs();
			return -ENOMEM;
		}

		per_cpu(vmxarea_bs, cpu) = vmcs;
	}
	return 0;
}

static __init int hardware_setup_bs(void)
{
	setup_vmcs_descriptor_bs();
	return alloc_kvm_area_bs();
}

static __init void hardware_enable_bs(void *garbage)
{
	int cpu = raw_smp_processor_id();
	u64 phys_addr = __pa(per_cpu(vmxarea_bs, cpu));
	u64 old;

	rdmsrl(MSR_IA32_FEATURE_CONTROL_BS, old);
	if ((old & 5) != 5)
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL_BS, old | 5);
	/* FIXME: not cpu hotplug safe */
	write_cr4_bs(read_cr4_bs() | CR4_VMXE_BS);
	asm volatile (ASM_VMX_VMXON_RAW_BS
					: 
					: "a" (&phys_addr), "m" (phys_addr)
					: "memory", "cc");
}

static void hardware_disable_bs(void *garbage)
{
	asm volatile (ASM_VMX_VMXOFF_BS : : : "cc");
}

static struct kvm_arch_ops_bs vmx_arch_ops_bs = {
	.cpu_has_kvm_support = cpu_has_kvm_support_bs,
	.disabled_by_bios = vmx_disabled_by_bios_bs,
	.hardware_setup = hardware_setup_bs,
	.hardware_enable = hardware_enable_bs,
	.hardware_disable = hardware_disable_bs,
};

static int __init vmx_init_bs(void)
{
	int r;

	r = kvm_init_arch_bs(&vmx_arch_ops_bs, THIS_MODULE);
	if (r)
		goto out;

	printk("Intel-VMX init-stage.\n");
out:
	return r;
}

static void __exit vmx_exit_bs(void)
{
}

module_init(vmx_init_bs);
module_exit(vmx_exit_bs);

MODULE_AUTHOR("BiscuitOS Copy");
MODULE_LICENSE("GPL");
