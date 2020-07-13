#ifndef _BISCUITOS_KVM_H
#define _BISCUITOS_KVM_H

#include <linux-bs/kvm.h>
#include "kvm_svm.h"

#define CR0_PE_MASK_BS				(1ULL << 0)
#define CR0_TS_MASK_BS				(1ULL << 3)
#define CR0_NE_MASK_BS				(1ULL << 5)
#define CR0_WP_MASK_BS				(1ULL << 16)
#define CR0_NW_MASK_BS				(1ULL << 29)
#define CR0_CD_MASK_BS				(1ULL << 30)
#define CR0_PG_MASK_BS				(1ULL << 31)

#define CR4_VME_MASK_BS				(1ULL << 0)
#define CR4_PSE_MASK_BS				(1ULL << 4)
#define CR4_PAE_MASK_BS				(1ULL << 5)
#define CR4_PGE_MASK_BS				(1ULL << 7)
#define CR4_VMXE_MASK_BS			(1ULL << 13)

#define MSR_IA32_TIME_STAMP_COUNTER_BS		0x010

#define KVM_MAX_VCPUS_BS			1
#define KVM_MEMORY_SLOTS_BS			4
#define KVM_NUM_MMU_PAGES_BS			256
#define KVM_MIN_FREE_MMU_PAGES_BS		5
#define KVM_REFILL_PAGES_BS			25

#define FX_IMAGE_SIZE_BS			512
#define FX_IMAGE_ALIGN_BS			16
#define FX_BUF_SIZE_BS				(2 * FX_IMAGE_SIZE_BS + \
							FX_IMAGE_ALIGN_BS)

#define ASM_VMX_VMCLEAR_RAX_BS			".byte 0x66, 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMPTRLD_RAX_BS			".byte 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMREAD_RDX_RAX_BS		".byte 0x0f, 0x78, 0xd0"
#define ASM_VMX_VMWRITE_RAX_RDX_BS		".byte 0x0f, 0x79, 0xd0"
#define ASM_VMX_VMXOFF_BS			".byte 0x0f, 0x01, 0xc4"
#define ASM_VMX_VMXON_RAW_BS			".byte 0xf3, 0x0f, 0xc7, 0x30"

#define TSS_IOPB_BASE_OFFSET_BS			0x66
#define TSS_BASE_SIZE_BS			0x68
#define TSS_IOPB_SIZE_BS			(65536 / 8)
#define TSS_REDIRECTION_SIZE_BS			(256 / 8)
#define RMODE_TSS_SIZE_BS			(TSS_BASE_SIZE_BS + \
						TSS_REDIRECTION_SIZE_BS + \
						TSS_IOPB_SIZE_BS + 1)

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

typedef unsigned long gva_t_bs;
typedef u64           gpa_t_bs;
typedef unsigned long gfn_t_bs;

typedef unsigned long hva_t_bs;
typedef u64           hpa_t_bs;
typedef unsigned long hfn_t_bs;

#define NR_PTE_CHAIN_ENTRIES_BS			5

struct kvm_pte_chain_bs {
	u64 *parent_ptes[NR_PTE_CHAIN_ENTRIES_BS];
	struct hlist_node link;
};

#define INVALID_PAGE_BS				(~(hpa_t_bs)0)
#define UNMAPPED_GVA_BS				(~(gpa_t_bs)0)
#define VALID_PAGE_BS(x)			((x) != INVALID_PAGE_BS)

struct kvm_vcpu_bs;

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

struct vmcs_bs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

#define vmx_msr_entry_bs	kvm_msr_entry_bs

/*
 * kvm_mmu_page_role, below, is defined as:
 *
 *   bits 0:3 - total guest paging levels (2-4, or zero for real mode)
 *   bits 4:7 - page table level for this shadow (1-4)
 *   bits 8:9 - page table quadrant for 2-level guests
 *   bits  16 - "metaphysical" - gfn is not a real page (huge page/real mode)
 */
union kvm_mmu_page_role_bs {
	unsigned word;
	struct {
		unsigned glevels : 4;
		unsigned level : 4;
		unsigned quadrant : 2;
		unsigned pad_for_nice_hex_output : 6;
		unsigned metaphysical : 1;
	};
};

struct kvm_mmu_page_bs {
	struct list_head link;
	struct hlist_node hash_link;

	/*
	 * The following two entries are used to key the shadow page in the 
	 * hash table.
	 */
	gfn_t_bs gfn;
	union kvm_mmu_page_role_bs role;

	hpa_t_bs page_hpa;
	unsigned long slot_bitmap; /* One bit set per slot which has memory 
				    * in the shadow page.
				    */
	int global;		/* Set if all ptes in this page are global */
	int multimapped;		/* More than one parent_pte? */
	int root_count;		/* Currently serving as active root */
	union {
		u64 *parent_pte;		/* !multimapped */
		struct hlist_head parent_ptes;	/* Multimapped, kvm_pte_chain */
	};
};

/*
 * x86 supports 3 paging modes (4-level 64-bit, 3-level 64-bit, and 2-level
 * 32-bit). The kvm_mmu structure abstracts the details of the current mmu
 * mode.
 */
struct kvm_mmu_bs {
	void (*new_cr3)(struct kvm_vcpu_bs *vcpu);
	int (*page_fault)(struct kvm_vcpu_bs *vcpu, gva_t_bs gva, u32 err);
	void (*free)(struct kvm_vcpu_bs *vcpu);
	gpa_t_bs (*gva_to_gpa)(struct kvm_vcpu_bs *vcpu, gva_t_bs gva);
	hpa_t_bs root_hpa;
	int root_level;
	int shadow_root_level;

	u64 *pae_root;
};

#define KVM_NR_MEM_OBJS_BS	20

struct kvm_mmu_memory_cache_bs {
	int nobjs;
	void *objects[KVM_NR_MEM_OBJS_BS];
};

/*
 * We don't want allocation failures within the mmu code, so we preallocate
 * enough memory for a single page fault in a cache.
 */
struct kvm_guest_debug_bs {
	int enabled;
	unsigned long bp[4];
	int singlestep;
};

enum {
	VCPU_REGS_RAX_BS = 0,
	VCPU_REGS_RCX_BS = 1,
	VCPU_REGS_RDX_BS = 2,
	VCPU_REGS_RBX_BS = 3,
	VCPU_REGS_RSP_BS = 4,
	VCPU_REGS_RBP_BS = 5,
	VCPU_REGS_RSI_BS = 6,
	VCPU_REGS_RDI_BS = 7,
	NR_VCPU_REGS_BS
};

enum {
	VCPU_SREG_CS_BS,
	VCPU_SREG_DS_BS,
	VCPU_SREG_ES_BS,
	VCPU_SREG_FS_BS,
	VCPU_SREG_GS_BS,
	VCPU_SREG_SS_BS,
	VCPU_SREG_TR_BS,
	VCPU_SREG_LDTR_BS,
};

struct kvm_vcpu_bs {
	struct kvm_bs *kvm;
	union {
		struct vmcs_bs *vmcs;
		struct vcpu_svm_bs *svm;
	};
	struct mutex mutex;
	int cpu;
	int launched;
	int interrupt_window_open;
	unsigned long irq_summary; /* bit vector: 1 per word in irq_pending */
#define NR_IRQ_WORDS_BS	KVM_IRQ_BITMAP_SIZE_BS(unsigned long)
	unsigned long irq_pending[NR_IRQ_WORDS_BS];
	unsigned long regs[NR_VCPU_REGS_BS]; /* for rsp: vcpu_load_rsp_rip() */
	unsigned long rip;	/* needs vcpu_load_rsp_rip() */

	unsigned long cr0;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long cr8;
	u64 pdptrs[4]; /* pae */
	u64 shadow_efer;
	u64 apic_base;
	u64 ia32_misc_enable_msr;
	int nmsrs;
	struct vmx_msr_entry_bs *guest_msrs;
	struct vmx_msr_entry_bs *host_msrs;

	struct list_head free_pages;
	struct kvm_mmu_page_bs page_header_buf[KVM_NUM_MMU_PAGES_BS];
	struct kvm_mmu_bs mmu;

	struct kvm_mmu_memory_cache_bs mmu_pte_chain_cache;
	struct kvm_mmu_memory_cache_bs mmu_rmap_desc_cache;

	gfn_t_bs last_pt_write_gfn;
	int last_pt_write_count;

	struct kvm_guest_debug_bs guest_debug;

	char fx_buf[FX_BUF_SIZE_BS];
	char *host_fx_image;
	char *guest_fx_image;

	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	unsigned char mmio_data[8];
	gpa_t_bs mmio_phys_addr;

	struct {
		int active;
		u8 save_iopl;
		struct kvm_save_segment_bs {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} tr, es, ds, fs, gs;
	} rmode;
	
};

struct kvm_memory_slot_bs {
	gfn_t_bs base_gfn;
	unsigned long npages;
	unsigned long flags;
	struct page **phys_mem;
	unsigned long *dirty_bitmap;
};

struct kvm_bs {
	spinlock_t lock;	/* protects everything expect vcpus */
	int nmemslots;
	struct kvm_memory_slot_bs memslots[KVM_MEMORY_SLOTS_BS];
	/*
	 * Hash table of struct kvm_mmu_page.
	 */
	struct list_head active_mmu_pages;
	int n_free_mmu_pages;
	struct hlist_head mmu_page_hash[KVM_NUM_MMU_PAGES_BS];
	struct kvm_vcpu_bs vcpus[KVM_MAX_VCPUS_BS];
	int memory_config_version;
	int busy;
	unsigned long rmap_overflow;
};

struct descriptor_table_bs {
	u16 limit;
	unsigned long base;
} __attribute__((packed));


struct kvm_arch_ops_bs {
	int (*cpu_has_kvm_support)(void);		/* __init */
	int (*disabled_by_bios)(void);			/* __init */
	void (*hardware_enable)(void *dummy);		/* __init */
	void (*hardware_disable)(void *dummy);
	int (*hardware_setup)(void);
	void (*hardware_unsetup)(void);

	int (*vcpu_create)(struct kvm_vcpu_bs *vcpu);
	void (*vcpu_free)(struct kvm_vcpu_bs *vcpu);

	struct kvm_vcpu_bs *(*vcpu_load)(struct kvm_vcpu_bs *vcpu);
	void (*vcpu_put)(struct kvm_vcpu_bs *vcpu);

	int (*set_guest_debug)(struct kvm_vcpu_bs *vcpu,
				struct kvm_debug_guest_bs *dbg);
	int (*get_msr)(struct kvm_vcpu_bs *vcpu, u32 msr_index, u64 *pdata);
	int (*set_msr)(struct kvm_vcpu_bs *vcpu, u32 msr_index, u64 data);
	u64 (*get_segment_base)(struct kvm_vcpu_bs *vcpu, int seg);
	void (*get_segment)(struct kvm_vcpu_bs *vcpu,
				struct kvm_segment_bs *var, int seg);
	void (*set_segment)(struct kvm_vcpu_bs *vcpu,
				struct kvm_segment_bs *var, int seg);
	void (*get_cs_db_l_bits)(struct kvm_vcpu_bs *vcpu, int *db, int *l);
	void (*decache_cr0_cr4_guest_bits)(struct kvm_vcpu_bs *vcpu);
	void (*set_cr0)(struct kvm_vcpu_bs *vcpu, unsigned long cr0);
	void (*set_cr0_no_modeswitch)(struct kvm_vcpu_bs *vcpu,
					unsigned long cr0);
	void (*set_cr3)(struct kvm_vcpu_bs *vcpu, unsigned long cr3);
	void (*set_cr4)(struct kvm_vcpu_bs *vcpu, unsigned long cr4);
	void (*set_efer)(struct kvm_vcpu_bs *vcpu, u64 efer);
	void (*get_idt)(struct kvm_vcpu_bs *vcpu, 
					struct descriptor_table_bs *dt);
	void (*set_idt)(struct kvm_vcpu_bs *vcpu,
					struct descriptor_table_bs *dt);
	void (*get_gdt)(struct kvm_vcpu_bs *vcpu,
					struct descriptor_table_bs *dt);
	void (*set_gdt)(struct kvm_vcpu_bs *vcpu,
					struct descriptor_table_bs *dt);
	unsigned long (*get_dr)(struct kvm_vcpu_bs *vcpu, int dr);
	void (*set_dr)(struct kvm_vcpu_bs *vcpu, int dr, unsigned long value,
					int *exception);
	void (*cache_regs)(struct kvm_vcpu_bs *vcpu);
	void (*decache_regs)(struct kvm_vcpu_bs *vcpu);
	unsigned long (*get_rflags)(struct kvm_vcpu_bs *vcpu, 
					unsigned long reflags);
	void (*set_rflags)(struct kvm_vcpu_bs *vcpu, unsigned long rflags);

	void (*invlpg)(struct kvm_vcpu_bs *vcpu, gva_t_bs addr);
	void (*tlb_flush)(struct kvm_vcpu_bs *vcpu);
	void (*inject_page_fault)(struct kvm_vcpu_bs *vcpu,
					unsigned long addr, u32 err_code);
	void (*inject_gp)(struct kvm_vcpu_bs *vcpu, unsigned err_code);

	int (*run)(struct kvm_vcpu_bs *vcpu, struct kvm_run_bs *run);
	int (*vcpu_setup)(struct kvm_vcpu_bs *vcpu);
	void (*skip_emulated_instruction)(struct kvm_vcpu_bs *vcpu);
};

static inline struct kvm_mmu_page_bs *page_header_bs(hpa_t_bs shadow_page)
{
	struct page *page = pfn_to_page(shadow_page >> PAGE_SHIFT);

	return (struct kvm_mmu_page_bs *)page->private;
}

unsigned long segment_base_bs(u16 selector);

static inline int is_paging_bs(struct kvm_vcpu_bs *vcpu)
{
	return vcpu->cr0 & CR0_PG_MASK_BS;
}

static inline int is_long_mode_bs(struct kvm_vcpu_bs *vcpu)
{
	return 0;
}

static inline int is_pae_bs(struct kvm_vcpu_bs *vcpu)
{
	return vcpu->cr4 & CR4_PAE_MASK_BS;
}

static inline unsigned long read_tr_base_bs(void)
{
	u16 tr;
	asm ("str %0" : "=g" (tr));
	return segment_base_bs(tr);
}

static inline void get_gdt_bs(struct descriptor_table_bs *table)
{
	asm ("sgdt %0" : "=m" (*table));
}

struct kvm_memory_slot_bs *gfn_to_memslot_bs(struct kvm_bs *kvm, gfn_t_bs gfn);

static inline struct page *_gfn_to_page_bs(struct kvm_bs *kvm, gfn_t_bs gfn)
{
	struct kvm_memory_slot_bs *slot = gfn_to_memslot_bs(kvm, gfn);
	return (slot) ? slot->phys_mem[gfn - slot->base_gfn] : NULL;
}

#define kvm_printf_bs(kvm, fmt ...) printk(KERN_DEBUG fmt)


int kvm_init_arch_bs(struct kvm_arch_ops_bs *ops, struct module *module);
int kvm_mmu_setup_bs(struct kvm_vcpu_bs *vcpu);
int kvm_mmu_create_bs(struct kvm_vcpu_bs *vcpu);
void kvm_mmu_destroy_bs(struct kvm_vcpu_bs *vcpu);

extern struct kvm_arch_ops_bs *kvm_arch_ops_bs;

#define BS_DUP() printk("Expand..%s-%s-%d\n", __FILE__, __func__, __LINE__)

#endif
