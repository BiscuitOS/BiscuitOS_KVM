#ifndef _BISCUITOS_LINUX_KVM_H
#define _BISCUITOS_LINUX_KVM_H

/*
 * Userspace interface for /dev/kvm - kernel based virtual machine
 *
 * Note: this interface is considered experimental and may change without
 *       notice.
 */
#include <asm/types.h>
#include <linux/ioctl.h>

#define KVM_API_VERSION_BS			2

/*
 * Architectural interrupt line count, and the size of the bitmap needed
 * to hold them.
 */
#define KVM_NR_INTERRUPTS_BS			256
#define KVM_IRQ_BITMAP_SIZE_BYTES_BS		((KVM_NR_INTERRUPTS_BS + 7) / 8)
#define KVM_IRQ_BITMAP_SIZE_BS(type)		(KVM_IRQ_BITMAP_SIZE_BYTES_BS /\
							sizeof(type))

/* for KVM_GREATE_MEMORY_REGION */
struct kvm_memory_region_bs {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
};

/* for KVM_RUN */
struct kvm_run_bs {
	/* in */
	__u32 vcpu;
	__u32 emulated;		/* skip current instruction */
	__u32 mmio_completed;	/* mmio request completed */
	__u8  request_interrupt_window;
	__u8  padding1[3];

	/* out */
	__u32 exit_type;
	__u32 exit_reason;
	__u32 instruction_length;
	__u8  ready_for_interrupt_injection;
	__u8  if_flag;
	__u16 padding2;
	__u64 acpi_base;

	union {
		/* KVM_EXIT_UNKNOWN */
		struct {
			__u32 hardware_exit_reason;
		} hw;
		/* KVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* KVM_EXIT_IO */
		struct {
#define KVM_EXIT_IO_IN_BS	0
#define KVM_EXIT_IO_OUT		1
			__u8 direction;
			__u8 size; /* bytes */
			__u8 string;
			__u8 string_down;
			__u8 rep;
			__u8 pad;
			__u16 port;
			__u64 count;
			union {
				__u64 address;
				__u32 value;
			};
		} io;
		struct {
		} debug;
		/* KVM_EXIT_MMIO */
		struct {
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
	};
};

/* for KVM_GET_REGS and KVM_SET_REGS */
struct kvm_regs_bs {
	/* in */
	__u32 vcpu;
	__u32 padding;

	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8, r9, r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

struct kvm_segment_bs {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};

struct kvm_msr_entry_bs {
	__u32 index;
	__u32 reserved;
	__u64 data;
};

/* for KVM_GET_MSRS and KVM_SET_MSRS */
struct kvm_msrs_bs {
	__u32 vcpu;
	__u32 nmsrs;	/* number of msrs in entries */

	struct kvm_msr_entry_bs entries[0];
};

/* for KVM_GET_MSR_INDEX_LIST */
struct kvm_msr_list_bs {
	__u32 nmsrs;	/* number of msrs in entries */
	__u32 indices[0];
};

/* for KVM_TRANSLATE */
struct kvm_translation_bs {
	/* in */
	__u64 linear_address;
	__u32 vcpu;
	__u32 padding;

	/* out */
	__u64 physical_address;
	__u8  valid;
	__u8  writable;
	__u8  usemode;
};

/* for KVM_INTERRUPT */
struct kvm_interrupt_bs {
	/* in */
	__u32 vcpu;
	__u32 irq;
};

/* for KVM_GET_DIRTY_LOG */
struct kvm_dirty_log_bs {
	__u32 slot;
	__u32 padding;
	union {
		void __user *dirty_bitmap; /* one bit per page */
		__u64 paddings;
	};
};

struct kvm_breakpoint_bs {
	__u32 enabled;
	__u32 padding;
	__u64 address;
};

/* for KVM_DEBUG_GUEST */
struct kvm_debug_guest_bs {
	/* int */
	__u32 vcpu;
	__u32 enabled;
	struct kvm_breakpoint_bs breakpoints[4];
	__u32 singlestep;
};

#define KVMIO_BS	0xAE

#define KVM_GET_API_VERSION_BS		_IO(KVMIO_BS, 1)
#define KVM_RUN_BS			_IOWR(KVMIO_BS, 2, struct kvm_run_bs)
#define KVM_GET_REGS_BS			_IOWR(KVMIO_BS, 3, struct kvm_regs_bs)
#define KVM_SET_REGS_BS			_IOW(KVMIO_BS, 4, struct kvm_regs_bs)
#define KVM_GET_SREGS_BS		_IOWR(KVMIO_BS, 5, struct kvm_sregs_bs)
#define KVM_SET_SREGS_BS		_IOW(KVMIO_BS, 6, struct kvm_sregs_bs)
#define KVM_TRANSLATE_BS		_IOWR(KVMIO_BS, 7,		\
						struct kvm_translation_bs)
#define KVM_INTERRUPT_BS		_IOW(KVMIO_BS, 8, 		\
						struct kvm_interrupt_bs)
#define KVM_DEBUG_GUEST_BS		_IOW(KVMIO_BS, 9,		\
						struct kvm_debug_guest_bs)
#define KVM_SET_MEMORY_REGION_BS	_IOW(KVMIO_BS, 10, 		\
						struct kvm_memory_region_bs)
/* In order compatile linux 5.0 */
//#define KVM_CREATE_VCPU_BS		_IOW(KVMIO_BS, 11, int /* vcpu_slot */)
#define KVM_CREATE_VCPU_BS		_IO(KVMIO_BS, 0x41/* vcpu_slot */)
#define KVM_GET_DIRTY_LOG_BS		_IOW(KVMIO_BS, 12, 		\
						struct kvm_dirty_log_bs)
#define KVM_GET_MSRS_BS			_IOWR(KVMIO_BS, 13, struct kvm_msrs_bs)
#define KVM_SET_MSRS_BS			_IOWR(KVMIO_BS, 14, struct kvm_msrs_bs)
#define KVM_GET_MSR_INDEX_LIST_BS	_IOWR(KVMIO_BS, 15, 		\
						struct kvm_msr_list_bs)

#endif
