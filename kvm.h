#ifndef _BISCUITOS_KVM_H
#define _BISCUITOS_KVM_H

#define MSR_IA32_TIME_STAMP_COUNTER_BS		0x010

/*
 * Address types:
 *
 * gva - guest virtual addresss
 * gpa - guest physical address
 * gfn - guest frame number
 * hva - host virtal address
 * hpa - host physical address
 * hfn - host frame number
 */

typedef unsigned long gva_t;
typedef u64           gpa_t;
typedef unsigned long gfn_t;

typedef unsigned long hva_t;
typedef u64           hpa_t;
typedef unsigned long hfn_t;

struct kvm_stat_bs {
	u32 pf_fixed;
	u32 pf_guest;
	u32 tlb_flush;
	u32 invlpg;

	u32 exits;
	u32 io_exits;
	u32 mmio_exits;
	u32 signal_exits;
	u32 irq_window_exits;
	u32 halt_exits;
	u32 request_irq_exits;
	u32 irq_exits;
};

#endif
