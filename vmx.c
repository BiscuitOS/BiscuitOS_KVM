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
#include <linux/highmem.h>

#include <asm-bs/system.h>
#include <asm-bs/msr.h>
#include "kvm.h"
#include "vmx.h"

static DEFINE_PER_CPU(struct vmcs_bs *, vmxarea_bs);
static DEFINE_PER_CPU(struct vmcs_bs *, current_vmcs_bs);

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

static unsigned long vmcs_readl_bs(unsigned long field)
{
	unsigned long value;

	asm volatile (ASM_VMX_VMREAD_RDX_RAX_BS
			: "=a" (value)
			: "d" (field)
			: "cc");
	return value;
}

static u32 vmcs_read32_bs(unsigned long field)
{
	return vmcs_readl_bs(field);
}

static noinline void vmwrite_error_bs(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
		field, value, vmcs_read32_bs(VM_INSTRUCTION_ERROR_BS));
	dump_stack();
}

static void vmcs_writel_bs(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (ASM_VMX_VMWRITE_RAX_RDX_BS "; setna %0"
			: "=q" (error)
			: "a" (value), "d" (field)
			: "cc");
	if (unlikely(error))
		vmwrite_error_bs(field, value);
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

static struct vmcs_bs *alloc_vmcs_bs(void)
{
	return alloc_vmcs_cpu_bs(raw_smp_processor_id());
}

static void vmcs_clear_bs(struct vmcs_bs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (ASM_VMX_VMCLEAR_RAX_BS "; setna %0"
			: "=g" (error)
			: "a" (&phys_addr), "m" (phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
				vmcs, phys_addr);
}

static int vmx_create_vcpu_bs(struct kvm_vcpu_bs *vcpu)
{
	struct vmcs_bs *vmcs;

	vcpu->guest_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vcpu->guest_msrs)
		return -ENOMEM;

	vcpu->host_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vcpu->host_msrs)
		goto out_free_guest_msrs;

	vmcs = alloc_vmcs_bs();
	if (!vmcs)
		goto out_free_msrs;

	vmcs_clear_bs(vmcs);
	vcpu->vmcs = vmcs;
	vcpu->launched = 0;

	return 0;

out_free_msrs:
	kfree(vcpu->host_msrs);
	vcpu->host_msrs = NULL;

out_free_guest_msrs:
	kfree(vcpu->guest_msrs);
	vcpu->guest_msrs = NULL;

	return -ENOMEM;
}

static void __vcpu_clear_bs(void *arg)
{
	struct kvm_vcpu_bs *vcpu = arg;
	int cpu = raw_smp_processor_id();

	if (vcpu->cpu == cpu)
		vmcs_clear_bs(vcpu->vmcs);
	if (per_cpu(current_vmcs_bs, cpu) == vcpu->vmcs)
		per_cpu(current_vmcs_bs, cpu) = NULL;
}

/*
 * Switch to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static struct kvm_vcpu_bs *vmx_vcpu_load_bs(struct kvm_vcpu_bs *vcpu)
{
	u64 phys_addr = __pa(vcpu->vmcs);
	int cpu;

	cpu = get_cpu();

	if (vcpu->cpu != cpu) {
		smp_call_function(__vcpu_clear_bs, vcpu, 1);
		vcpu->launched = 0;
	}

	if (per_cpu(current_vmcs_bs, cpu) != vcpu->vmcs) {
		u8 error;

		per_cpu(current_vmcs_bs, cpu) = vcpu->vmcs;
		asm volatile (ASM_VMX_VMPTRLD_RAX_BS "; setna %0"
				: "=g" (error)
				: "a" (&phys_addr), "m" (phys_addr)
				: "cc");
		if (error)
			printk(KERN_ERR "kvm: vmptrld %p/%llx fail\n",
					vcpu->vmcs, phys_addr);
	}

	if (vcpu->cpu != cpu) {
		struct descriptor_table_bs dt;
		unsigned long sysenter_esp;

		vcpu->cpu = cpu;
		/*
		 * Linux user per-cpu TSS and GDT, so set these when sitching
		 * processors.
		 */
		vmcs_writel_bs(HOST_TR_BASE_BS, read_tr_base_bs()); /* 22.2.4 */
		get_gdt_bs(&dt);
		vmcs_writel_bs(HOST_GDTR_BASE_BS, dt.base); /* 22.2.4 */

		rdmsrl_bs(MSR_IA32_SYSENTER_ESP_BS, sysenter_esp);
		vmcs_writel_bs(HOST_IA32_SYSENTER_ESP_BS, sysenter_esp);
	}

	return vcpu;
}

static void vmx_set_cr3_bs(struct kvm_vcpu_bs *vcpu, unsigned long cr3)
{
	vmcs_writel_bs(GUEST_CR3_BS, cr3);
}

static int rmode_tss_base_bs(struct kvm_bs *kvm)
{
	gfn_t_bs base_gfn = kvm->memslots[0].base_gfn + 
						kvm->memslots[0].npages - 3;
	return base_gfn << PAGE_SHIFT;
}

static int init_rmode_tss_bs(struct kvm_bs *kvm)
{
	struct page *p1, *p2, *p3;
	gfn_t_bs fn = rmode_tss_base_bs(kvm) >> PAGE_SHIFT;
	char *page;

	p1 = _gfn_to_page_bs(kvm, fn++);
	p2 = _gfn_to_page_bs(kvm, fn++);
	p3 = _gfn_to_page_bs(kvm, fn);

	if (!p1 || !p2 || !p3) {
		kvm_printf_bs(kvm, "%s: gfn_to_page failed\n", __func__);
		return 0;
	}

	page = kmap_atomic(p1);
	memset(page, 0, PAGE_SIZE);
	*(u16*)(page + 0x66) = TSS_BASE_SIZE_BS + TSS_REDIRECTION_SIZE_BS;
	kunmap_atomic(page);

	page = kmap_atomic(p2);
	memset(page, 0, PAGE_SIZE);
	kunmap_atomic(page);

	page = kmap_atomic(p3);
	memset(page, 0, PAGE_SIZE);
	*(page + RMODE_TSS_SIZE_BS - 2 * PAGE_SIZE - 1) = ~0;
	kunmap_atomic(page);

	return 1;
}

/*
 * Setup up the vmcs for emulated real mode.
 */
static int vmx_vcpu_setup_bs(struct kvm_vcpu_bs *vcpu)
{
	u32 host_sysenter_cs;
	u32 junk;
	unsigned long a;
	struct descriptor_table_bs dt;
	int i;
	int ret = 0;
	int nr_good_msrs;

	if (!init_rmode_tss_bs(vcpu->kvm)) {
		ret = -ENOMEM;
		goto out;
	}
	
	return 0;

out:
	return ret;
}

static struct kvm_arch_ops_bs vmx_arch_ops_bs = {
	.cpu_has_kvm_support = cpu_has_kvm_support_bs,
	.disabled_by_bios = vmx_disabled_by_bios_bs,
	.hardware_setup = hardware_setup_bs,
	.hardware_enable = hardware_enable_bs,
	.hardware_disable = hardware_disable_bs,

	.vcpu_create = vmx_create_vcpu_bs,

	.vcpu_load = vmx_vcpu_load_bs,

	.set_cr3 = vmx_set_cr3_bs,

	.vcpu_setup = vmx_vcpu_setup_bs,
};

static int __init vmx_init_bs(void)
{
	return kvm_init_arch_bs(&vmx_arch_ops_bs, THIS_MODULE);
}

static void __exit vmx_exit_bs(void)
{
}

module_init(vmx_init_bs);
module_exit(vmx_exit_bs);

MODULE_AUTHOR("BiscuitOS Copy");
MODULE_LICENSE("GPL");
