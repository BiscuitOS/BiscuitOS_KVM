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
#include <linux/smp.h>
#include <linux/reboot.h>

#include <linux-bs/kvm.h>
#include <asm-bs/msr.h>
#include "kvm.h"

struct kvm_arch_ops_bs *kvm_arch_ops_bs;
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

static int kvm_reboot_bs(struct notifier_block *notifier, unsigned long val,
				void *v)
{
	if (val == SYS_RESTART) {
		/*
		 * Some (well, at least mine) BIOSes hang on reboot if
		 * in vmx root mode.
		 */
		printk(KERN_INFO "kvm: existing hardware virtualization\n");
		on_each_cpu(kvm_arch_ops_bs->hardware_disable, 0, 1);
	}

	return NOTIFY_OK;
}

static struct notifier_block kvm_reboot_notifier_bs = {
	.notifier_call = kvm_reboot_bs,
	.priority = 0,
};

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

static void vcpu_put_bs(struct kvm_vcpu_bs *vcpu)
{
	kvm_arch_ops_bs->vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);
}

static int vcpu_slot_bs(struct kvm_vcpu_bs *vcpu)
{
	return vcpu - vcpu->kvm->vcpus;
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
static struct kvm_vcpu_bs *vcpu_load_bs(struct kvm_bs *kvm, int vcpu_slot)
{
	struct kvm_vcpu_bs *vcpu = &kvm->vcpus[vcpu_slot];

	mutex_lock(&vcpu->mutex);
	if (unlikely(!vcpu->vmcs)) {
		mutex_unlock(&vcpu->mutex);
		return 0;
	}
	return kvm_arch_ops_bs->vcpu_load(vcpu);
}

static void kvm_free_vcpu_bs(struct kvm_vcpu_bs *vcpu)
{
	vcpu_load_bs(vcpu->kvm, vcpu_slot_bs(vcpu));
	kvm_mmu_destroy_bs(vcpu);
	vcpu_put_bs(vcpu);
	kvm_arch_ops_bs->vcpu_free(vcpu);
}

static void kvm_free_vcpus_bs(struct kvm_bs *kvm)
{
	unsigned int i;

	for (i = 0; i < KVM_MAX_VCPUS_BS; ++i)
		kvm_free_vcpu_bs(&kvm->vcpus[i]);
}

static int kvm_dev_open_bs(struct inode *inode, struct file *filp)
{
	struct kvm_bs *kvm = kzalloc(sizeof(struct kvm_bs), GFP_KERNEL);
	int i;

	if (!kvm)
		return -ENOMEM;

	spin_lock_init(&kvm->lock);
	INIT_LIST_HEAD(&kvm->active_mmu_pages);
	for (i = 0; i < KVM_MAX_VCPUS_BS; ++i) {
		struct kvm_vcpu_bs *vcpu = &kvm->vcpus[i];

		mutex_init(&vcpu->mutex);
		vcpu->kvm = kvm;
		vcpu->mmu.root_hpa = INVALID_PAGE_BS;
		INIT_LIST_HEAD(&vcpu->free_pages);
	}
	filp->private_data = kvm;
	return 0;
}

static int kvm_dev_release_bs(struct inode *inode, struct file *filp)
{
	BS_DUP();
	return 0;
}

static inline int valid_vcpu_bs(int n)
{
	return likely(n >= 0 && n < KVM_MAX_VCPUS_BS);
}

/*
 * Creates some virtual cpus. Good luck creating more than one.
 */
static int kvm_dev_ioctl_create_vcpu_bs(struct kvm_bs *kvm, int n)
{
	int r;
	struct kvm_vcpu_bs *vcpu;

	r = -EINVAL;
	if (!valid_vcpu_bs(n))
		goto out;

	vcpu = &kvm->vcpus[n];

	mutex_lock(&vcpu->mutex);

	if (vcpu->vmcs) {
		mutex_unlock(&vcpu->mutex);
		return -EEXIST;
	}

	vcpu->host_fx_image = (char *)ALIGN((hva_t_bs)vcpu->fx_buf,
					FX_IMAGE_ALIGN_BS);
	vcpu->guest_fx_image = vcpu->host_fx_image + FX_IMAGE_SIZE_BS;

	vcpu->cpu = -1;	/* First load will set up TR */
	r = kvm_arch_ops_bs->vcpu_create(vcpu);
	if (r < 0)
		goto out_free_vcpus;

	r = kvm_mmu_create_bs(vcpu);
	if (r < 0)
		goto out_free_vcpus;

	kvm_arch_ops_bs->vcpu_load(vcpu);
	r = kvm_mmu_setup_bs(vcpu);
	if (r >= 0)
		r = kvm_arch_ops_bs->vcpu_setup(vcpu);
	vcpu_put_bs(vcpu);

	if (r < 0)
		goto out_free_vcpus;

	return 0;

out_free_vcpus:
	kvm_free_vcpu_bs(vcpu);
	mutex_unlock(&vcpu->mutex);
out:
	return r;
}

static long kvm_dev_ioctl_bs(struct file *filp,
				unsigned int ioctl, unsigned long arg)
{
	struct kvm_bs *kvm = filp->private_data;
	int r = -EINVAL;

	switch (ioctl) {
	case KVM_GET_API_VERSION_BS:
		r = KVM_API_VERSION_BS;
		break;
	case KVM_CREATE_VCPU_BS: {
		r = kvm_dev_ioctl_create_vcpu_bs(kvm, arg);
		if (r)
			goto out;
		break;
	}
	}
out:
	return r;
}

static int kvm_dev_mmap_bs(struct file *file, struct vm_area_struct *vma)
{
	BS_DUP();
	return 0;
}

static struct file_operations kvm_chardev_ops_bs = {
	.open		= kvm_dev_open_bs,
	.release	= kvm_dev_release_bs,
	.unlocked_ioctl	= kvm_dev_ioctl_bs,
	.compat_ioctl	= kvm_dev_ioctl_bs,
	.mmap		= kvm_dev_mmap_bs,
};

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
	int r;

	if (kvm_arch_ops_bs) {
		printk(KERN_ERR "kvm: already loaded the other module\n");
		return -EEXIST;
	}

	if (!ops->cpu_has_kvm_support()) {
		printk(KERN_ERR "kvm: no hardware support\n");
		return -EOPNOTSUPP;
	}

	if (ops->disabled_by_bios()) {
		printk(KERN_ERR "kvm: disabled by bios\n");
		return -EOPNOTSUPP;
	}

	kvm_arch_ops_bs = ops;

	r = kvm_arch_ops_bs->hardware_setup();
	if (r < 0)
		return r;

	on_each_cpu(kvm_arch_ops_bs->hardware_enable, 0, 1);
	register_reboot_notifier(&kvm_reboot_notifier_bs);

	kvm_chardev_ops_bs.owner = module;
	return 0;
}

EXPORT_SYMBOL_GPL(kvm_init_arch_bs);

MODULE_AUTHOR("BiscuitOS Copy");
MODULE_LICENSE("GPL");
