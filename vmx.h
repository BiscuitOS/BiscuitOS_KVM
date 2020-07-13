#ifndef _BISCUITOS_VMX_H
#define _BISCUITOS_VMX_H

/*
 * vmx.h: VMX Architecture related definitions
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * A few random additions are:
 * Copyright (C) 2006 Qumranet
 *    Avi Kivity <avi@qumranet.com>
 *    Yaniv Kamay <yaniv@qumranet.com>
 *
 */

/* VMCS Encodings */
enum vmcs_field {
	GUEST_ES_SELECTOR_BS               = 0x00000800,
	GUEST_CS_SELECTOR_BS               = 0x00000802,
	GUEST_SS_SELECTOR_BS               = 0x00000804,
	GUEST_DS_SELECTOR_BS               = 0x00000806,
	GUEST_FS_SELECTOR_BS               = 0x00000808,
	GUEST_GS_SELECTOR_BS               = 0x0000080a,
	GUEST_LDTR_SELECTOR_BS             = 0x0000080c,
	GUEST_TR_SELECTOR_BS               = 0x0000080e,
	HOST_ES_SELECTOR_BS                = 0x00000c00,
	HOST_CS_SELECTOR_BS                = 0x00000c02,
	HOST_SS_SELECTOR_BS                = 0x00000c04,
	HOST_DS_SELECTOR_BS                = 0x00000c06,
	HOST_FS_SELECTOR_BS                = 0x00000c08,
	HOST_GS_SELECTOR_BS                = 0x00000c0a,
	HOST_TR_SELECTOR_BS                = 0x00000c0c,
	IO_BITMAP_A_BS                     = 0x00002000,
	IO_BITMAP_A_HIGH_BS                = 0x00002001,
	IO_BITMAP_B_BS                     = 0x00002002,
	IO_BITMAP_B_HIGH_BS                = 0x00002003,
	MSR_BITMAP_BS                      = 0x00002004,
	MSR_BITMAP_HIGH_BS                 = 0x00002005,
	VM_EXIT_MSR_STORE_ADDR_BS          = 0x00002006,
	VM_EXIT_MSR_STORE_ADDR_HIGH_BS     = 0x00002007,
	VM_EXIT_MSR_LOAD_ADDR_BS           = 0x00002008,
	VM_EXIT_MSR_LOAD_ADDR_HIGH_BS      = 0x00002009,
	VM_ENTRY_MSR_LOAD_ADDR_BS          = 0x0000200a,
	VM_ENTRY_MSR_LOAD_ADDR_HIGH_BS     = 0x0000200b,
	TSC_OFFSET_BS                      = 0x00002010,
	TSC_OFFSET_HIGH_BS                 = 0x00002011,
	VIRTUAL_APIC_PAGE_ADDR_BS          = 0x00002012,
	VIRTUAL_APIC_PAGE_ADDR_HIGH_BS     = 0x00002013,
	VMCS_LINK_POINTER_BS               = 0x00002800,
	VMCS_LINK_POINTER_HIGH_BS          = 0x00002801,
	GUEST_IA32_DEBUGCTL_BS             = 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH_BS        = 0x00002803,
	PIN_BASED_VM_EXEC_CONTROL_BS       = 0x00004000,
	CPU_BASED_VM_EXEC_CONTROL_BS       = 0x00004002,
	EXCEPTION_BITMAP_BS                = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK_BS      = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH_BS     = 0x00004008,
	CR3_TARGET_COUNT_BS                = 0x0000400a,
	VM_EXIT_CONTROLS_BS                = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT_BS         = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT_BS          = 0x00004010,
	VM_ENTRY_CONTROLS_BS               = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT_BS         = 0x00004014,
	VM_ENTRY_INTR_INFO_FIELD_BS        = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE_BS   = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN_BS        = 0x0000401a,
	TPR_THRESHOLD_BS                   = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL_BS       = 0x0000401e,
	VM_INSTRUCTION_ERROR_BS            = 0x00004400,
	VM_EXIT_REASON_BS                  = 0x00004402,
	VM_EXIT_INTR_INFO_BS               = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE_BS         = 0x00004406,
	IDT_VECTORING_INFO_FIELD_BS        = 0x00004408,
	IDT_VECTORING_ERROR_CODE_BS        = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN_BS         = 0x0000440c,
	VMX_INSTRUCTION_INFO_BS            = 0x0000440e,
	GUEST_ES_LIMIT_BS                  = 0x00004800,
	GUEST_CS_LIMIT_BS                  = 0x00004802,
	GUEST_SS_LIMIT_BS                  = 0x00004804,
	GUEST_DS_LIMIT_BS                  = 0x00004806,
	GUEST_FS_LIMIT_BS                  = 0x00004808,
	GUEST_GS_LIMIT_BS                  = 0x0000480a,
	GUEST_LDTR_LIMIT_BS                = 0x0000480c,
	GUEST_TR_LIMIT_BS                  = 0x0000480e,
	GUEST_GDTR_LIMIT_BS                = 0x00004810,
	GUEST_IDTR_LIMIT_BS                = 0x00004812,
	GUEST_ES_AR_BYTES_BS               = 0x00004814,
	GUEST_CS_AR_BYTES_BS               = 0x00004816,
	GUEST_SS_AR_BYTES_BS               = 0x00004818,
	GUEST_DS_AR_BYTES_BS               = 0x0000481a,
	GUEST_FS_AR_BYTES_BS               = 0x0000481c,
	GUEST_GS_AR_BYTES_BS               = 0x0000481e,
	GUEST_LDTR_AR_BYTES_BS             = 0x00004820,
	GUEST_TR_AR_BYTES_BS               = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO_BS     = 0x00004824,
	GUEST_ACTIVITY_STATE_BS            = 0X00004826,
	GUEST_SYSENTER_CS_BS               = 0x0000482A,
	HOST_IA32_SYSENTER_CS_BS           = 0x00004c00,
	CR0_GUEST_HOST_MASK_BS             = 0x00006000,
	CR4_GUEST_HOST_MASK_BS             = 0x00006002,
	CR0_READ_SHADOW_BS                 = 0x00006004,
	CR4_READ_SHADOW_BS                 = 0x00006006,
	CR3_TARGET_VALUE0_BS               = 0x00006008,
	CR3_TARGET_VALUE1_BS               = 0x0000600a,
	CR3_TARGET_VALUE2_BS               = 0x0000600c,
	CR3_TARGET_VALUE3_BS               = 0x0000600e,
	EXIT_QUALIFICATION_BS              = 0x00006400,
	GUEST_LINEAR_ADDRESS_BS            = 0x0000640a,
	GUEST_CR0_BS                       = 0x00006800,
	GUEST_CR3_BS                       = 0x00006802,
	GUEST_CR4_BS                       = 0x00006804,
	GUEST_ES_BASE_BS                   = 0x00006806,
	GUEST_CS_BASE_BS                   = 0x00006808,
	GUEST_SS_BASE_BS                   = 0x0000680a,
	GUEST_DS_BASE_BS                   = 0x0000680c,
	GUEST_FS_BASE_BS                   = 0x0000680e,
	GUEST_GS_BASE_BS                   = 0x00006810,
	GUEST_LDTR_BASE_BS                 = 0x00006812,
	GUEST_TR_BASE_BS                   = 0x00006814,
	GUEST_GDTR_BASE_BS                 = 0x00006816,
	GUEST_IDTR_BASE_BS                 = 0x00006818,
	GUEST_DR7_BS                       = 0x0000681a,
	GUEST_RSP_BS                       = 0x0000681c,
	GUEST_RIP_BS                       = 0x0000681e,
	GUEST_RFLAGS_BS                    = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS_BS    = 0x00006822,
	GUEST_SYSENTER_ESP_BS              = 0x00006824,
	GUEST_SYSENTER_EIP_BS              = 0x00006826,
	HOST_CR0_BS                        = 0x00006c00,
	HOST_CR3_BS                        = 0x00006c02,
	HOST_CR4_BS                        = 0x00006c04,
	HOST_FS_BASE_BS                    = 0x00006c06,
	HOST_GS_BASE_BS                    = 0x00006c08,
	HOST_TR_BASE_BS                    = 0x00006c0a,
	HOST_GDTR_BASE_BS                  = 0x00006c0c,
	HOST_IDTR_BASE_BS                  = 0x00006c0e,
	HOST_IA32_SYSENTER_ESP_BS          = 0x00006c10,
	HOST_IA32_SYSENTER_EIP_BS          = 0x00006c12,
	HOST_RSP_BS                        = 0x00006c14,
	HOST_RIP_BS                        = 0x00006c16,
};
	
#define CR4_VMXE_BS				0x2000

#define MSR_IA32_VMX_BASIC_BS			0x480 /* 3-A.1 */
#define MSR_IA32_FEATURE_CONTROL_BS		0x03a /* 2-6.2 */
#define MSR_IA32_VMX_PINBASED_CTLS_BS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS_BS		0x482
#define MSR_IA32_VMX_EXIT_CTLS_BS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS_BS		0x484

#endif
