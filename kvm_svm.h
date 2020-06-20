#ifndef _BISCUITOS_KVM_SVM_H
#define _BISCUITOS_KVM_SVM_H

#include <asm-bs/msr.h>
#include "svm.h"

static const u32 host_save_msrs_bs[] = {
	MSR_IA32_SYSENTER_CS_BS,
	MSR_IA32_SYSENTER_ESP_BS,
	MSR_IA32_SYSENTER_EIP_BS,
	MSR_IA32_DEBUGCTLMSR_BS,
};

#define NR_HOST_SAVE_MSRS_BS	(sizeof(host_save_msrs_bs) / \
					sizeof(*host_save_msrs_bs))
#define NUM_DB_REGS_BS		4

struct vcpu_svm_bs {
	struct vmcb_bs *vmcb;
	unsigned long vmcb_pa;
	struct svm_cpu_data_bs *svm_data;
	uint64_t asid_generation;

	unsigned long cr0;
	unsigned long cr4;
	unsigned long db_regs[NUM_DB_REGS_BS];

	u64 next_rip;

	u64 host_msrs[NR_HOST_SAVE_MSRS_BS];
	unsigned long host_cr2;
	unsigned long host_db_regs[NUM_DB_REGS_BS];
	unsigned long host_dr6;
	unsigned long host_dr7;
};

#endif
