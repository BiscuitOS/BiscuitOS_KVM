#ifndef _BISCUITOS_SVM_H
#define _BISCUITOS_SVM_H

struct __attribute__ ((__packed__)) vmcb_control_area_bs {
	u16 intercept_cr_read;
	u16 intercept_cr_write;
	u16 intercept_dr_read;
	u16 intercept_dr_write;
	u32 intercept_exceptions;
	u64 intercept;
	u8 reserved_1[44];
	u64 iopm_base_pa;
	u64 msrpm_base_pa;
	u64 tsc_offset;
	u32 asid;
	u8 tlb_ctl;
	u8 reserved_2[3];
	u32 int_ctl;
	u32 int_vector;
	u32 int_state;
	u8 reserved_3[4];
	u32 exit_code;
	u32 exit_code_hi;
	u64 exit_info_1;
	u64 exit_info_2;
	u32 exit_int_info;
	u32 exit_int_info_err;
	u64 nested_ctl;
	u8 reserved_4[16];
	u32 event_inj;
	u32 event_inj_err;
	u64 nested_cr3;
	u64 lbr_ctl;
	u8 reserved_5[832];
};

struct __attribute__ ((__packed__)) vmcb_seg_bs {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
};

struct __attribute__ ((__packed__)) vmcb_save_area_bs {
	struct vmcb_seg_bs es;
	struct vmcb_seg_bs cs;
	struct vmcb_seg_bs ss;
	struct vmcb_seg_bs ds;
	struct vmcb_seg_bs fs;
	struct vmcb_seg_bs gs;
	struct vmcb_seg_bs gdtr;
	struct vmcb_seg_bs ldtr;
	struct vmcb_seg_bs idtr;
	struct vmcb_seg_bs tr;
	u8 reserved_1[43];
	u8 cpl;
	u8 reserved_2[4];
	u64 efer;
	u8 reserved_3[112];
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u8 reserved_4[88];
	u64 rsp;
	u8 reserved_5[24];
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_6[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;
};

struct __attribute__ ((__packed__)) vmcb_bs {
	struct vmcb_control_area_bs control;
	struct vmcb_save_area_bs save;
};

#endif
