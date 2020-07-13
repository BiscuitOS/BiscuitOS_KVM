/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * MMU support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <linux-bs/list.h>
#include "kvm.h"
#include "vmx.h"

#ifdef MMU_DEBUG_BS

#define pgprintk_bs(x...)	do { if (dbg) printk(x); } while (0)
#define rmap_printk_bs(x...)	do { if (dbg) printk(x); } while (0)

#else

#define pgprintk_bs(x...)	do { } while (0)
#define rmap_printk_bs(x...)	do { } while (0)

#endif

#define ASSERT_BS(x)							\
	if (!(x)) {							\
		printk(KERN_WARNING "assertion failed %s:%d: %s\n",	\
				__FILE__, __LINE__, #x);		\
	}

#define PT64_PT_BITS_BS			9
#define PT64_ENT_PER_PAGE_BS		(1 << PT64_PT_BITS_BS)
#define PT32_PT_BITS_BS			10
#define PT32_ENT_PER_PAGE_BS		(1 << PT32_PT_BITS_BS)

#define PT_WRITABLE_SHIFT_BS		1

#define PT_PRESENT_MASK_BS		(1ULL << 0)
#define PT_WRITABLE_MASK_BS		(1ULL << PT_WRITABLE_SHIFT_BS)
#define PT_USER_MASK_BS			(1ULL << 2)
#define PT_PWT_MASK_BS			(1ULL << 3)
#define PT_PCD_MASK_BS			(1ULL << 4)
#define PT_ACCESSED_MASK_BS		(1ULL << 5)
#define PT_DIRTY_MASK_BS		(1ULL << 6)
#define PT_PAGE_SIZE_MASK_BS		(1ULL << 7)
#define PT_PAT_MASK_BS			(1ULL << 7)
#define PT_GLOBAL_MASK_BS		(1ULL << 8)
#define PT64_NX_MASK_BS			(1ULL << 63)

#define PT_PAT_SHIFT_BS			7
#define PT_DIR_PAT_SHIFT_BS		12
#define PT_DIR_PAT_MASK_BS		(1ULL << PT_DIR_PAT_SHIFT_BS)

#define PT32_DIR_PSE36_SIZE_BS		4
#define PT32_DIR_PSE36_SHIFT_BS		13
#define PT32_DIR_PSE36_MASK_BS		(((1ULL << PT32_DIR_PSE36_SIZE_BS) - \
						1) << PT32_DIR_PSE36_SHIFT_BS)


#define PT32_PTE_COPY_MASK_BS		(PT_PRESENT_MASK_BS | \
					 PT_ACCESSED_MASK_BS | \
					 PT_DIRTY_MASK_BS | PT_GLOBAL_MASK_BS)

#define PT64_PTE_COPY_MASK_BS		(PT64_NX_MASK_BS | \
					 PT32_PTE_COPY_MASK_BS)

#define PT_FIRST_AVAIL_BITS_SHIFT_BS	9
#define PT64_SECOND_AVAIL_BITS_SHIFT_BS	52

#define PT_SHADOW_PS_MARK_BS		(1ULL << PT_FIRST_AVAIL_BITS_SHIFT_BS)
#define PT_SHADOW_IO_MARK_BS		(1ULL << PT_FIRST_AVAIL_BITS_SHIFT_BS)

#define PT_SHADOW_WRITABLE_SHIFT_BS	(PT_FIRST_AVAIL_BITS_SHIFT_BS + 1)
#define PT_SHADOW_WRITABLE_MASK_BS	(1ULL << PT_SHADOW_WRITABLE_SHIFT_BS)

#define PT_SHADOW_USER_SHIFT_BS		(PT_SHADOW_WRITABLE_SHIFT_BS + 1)
#define PT_SHADOW_USER_MASK_BS		(1ULL << (PT_SHADOW_USER_SHIFT_BS))

#define PT_SHADOW_BITS_OFFSET_BS	(PT_SHADOW_WRITABLE_SHIFT_BS - \
					 PT_WRITABLE_SHIFT_BS)

#define VALID_PAGE_BS(x) 		((x) != INVALID_PAGE_BS)

#define PT64_LEVEL_BITS_BS		9

#define PT64_LEVEL_SHIFT_BS(level)	(PAGE_SHIFT + (level - 1) * \
					 PT64_LEVEL_BITS_BS)

#define PT64_LEVEL_MASK_BS(level)	(((1ULL << PT64_LEVEL_BITS_BS) - 1) <<\
					 PT64_LEVEL_SHIFT_BS(level))

#define PT64_INDEX_BS(address, level)	(((address) >> \
					PT64_LEVEL_SHIFT_BS(level)) & \
					((1 << PT64_LEVEL_BITS_BS) - 1))

#define PT32_LEVEL_BITS_BS		10

#define PT32_LEVEL_SHIFT_BS(level)	(PAGE_SHIFT + (level - 1) * \
					 PT32_LEVEL_BITS_BS)

#define PT32_LEVEL_MASK_BS(level)	(((1ULL << PT32_LEVEL_BITS_BS) - 1) <<\
					PT32_LEVEL_SHIFT_BS(level))

#define PT32_INDEX_BS(address, level)	(((address) >> \
					PT32_LEVEL_SHIFT_BS(level)) & ((1 << \
					PT32_LEVEL_BITS_BS) - 1))

#define PT64_BASE_ADDR_MASK_BS		(((1ULL << 52) - 1) & PAGE_MASK)
#define PT64_DIR_BASE_ADDR_MASK_BS	(PT64_BASE_ADDR_MASK_BS & ~((1ULL << \
					(PAGE_SHIFT + PT64_LEVEL_BITS_BS)) - 1))

#define PT32_BASE_ADDR_MASK_BS		PAGE_MASK
#define PT32_DIR_BASE_ADDR_MASK_BS	(PAGE_MASK & ~((1ULL << (PAGE_SHIFT + \
					PT32_LEVEL_BITS_BS)) - 1))

#define PFERR_PRESENT_MASK_BS		(1U << 0)
#define PFERR_WRITE_MASK_BS		(1U << 1)
#define PFERR_USER_MASK_BS		(1U << 2)
#define PFERR_FETCH_MASK_BS		(1U << 4)

#define PT64_ROOT_LEVEL_BS		4
#define PT32_ROOT_LEVEL_BS		2
#define PT32E_ROOT_LEVEL_BS		3

#define PT_DIRECTORY_LEVEL_BS		2
#define PT_PAGE_TABLE_LEVEL_BS		1

#define RMAP_EXT_BS			4

struct kvm_rmap_desc_bs {
	u64 *shadow_ptes[RMAP_EXT_BS];
	struct kvm_rmap_desc_bs *more;
};

static int is_rmap_pte_bs(u64 pte)
{
	return (pte & (PT_WRITABLE_MASK_BS | PT_PRESENT_MASK_BS)) ==
		 (PT_WRITABLE_MASK_BS | PT_PRESENT_MASK_BS);
}

static void destroy_kvm_mmu_bs(struct kvm_vcpu_bs *vcpu)
{
	ASSERT_BS(vcpu);
	if (VALID_PAGE_BS(vcpu->mmu.root_hpa)) {
		vcpu->mmu.free(vcpu);
		vcpu->mmu.root_hpa = INVALID_PAGE_BS;
	}
}

static void
mmu_memory_cache_free_bs(struct kvm_mmu_memory_cache_bs *mc, void *obj)
{
	if (mc->nobjs < KVM_NR_MEM_OBJS_BS)
		mc->objects[mc->nobjs++] = obj;
	else
		kfree(obj);
}

static void mmu_free_pte_chain_bs(struct kvm_vcpu_bs *vcpu,
					struct kvm_pte_chain_bs *pc)
{
	mmu_memory_cache_free_bs(&vcpu->mmu_pte_chain_cache, pc);
}

static void mmu_page_remove_parent_pte_bs(struct kvm_vcpu_bs *vcpu,
		struct kvm_mmu_page_bs *page, u64 *parent_pte)
{
	BS_DUP();
}

static void kvm_mmu_put_page_bs(struct kvm_vcpu_bs *vcpu,
			struct kvm_mmu_page_bs *page, u64 *parent_pte)
{
	mmu_page_remove_parent_pte_bs(vcpu, page, parent_pte);
}

static void mmu_free_rmap_desc_bs(struct kvm_vcpu_bs *vcpu,
					struct kvm_rmap_desc_bs *rd)
{
	mmu_memory_cache_free_bs(&vcpu->mmu_rmap_desc_cache, rd);
}

static void rmap_desc_remove_entry_bs(struct kvm_vcpu_bs *vcpu,
		struct page *page, struct kvm_rmap_desc_bs *desc,
		int i, struct kvm_rmap_desc_bs *prev_desc)
{
	int j;

	for (j = RMAP_EXT_BS - 1; !desc->shadow_ptes[j] && j > i; --j)
		;
	desc->shadow_ptes[i] = desc->shadow_ptes[j];
	desc->shadow_ptes[j] = 0;
	if (j != 0)
		return;
	if (!prev_desc && !desc->more)
		page->private = (unsigned long)desc->shadow_ptes[0];
	else
		if (prev_desc)
			prev_desc->more = desc->more;
		else
			page->private = (unsigned long)desc->more;
	mmu_free_rmap_desc_bs(vcpu, desc);
}

static void rmap_remove_bs(struct kvm_vcpu_bs *vcpu, u64 *spte)
{
	struct page *page;
	struct kvm_rmap_desc_bs *desc;
	struct kvm_rmap_desc_bs *prev_desc;
	int i;

	if (!is_rmap_pte_bs(*spte))
		return;
	page = pfn_to_page((*spte & PT64_BASE_ADDR_MASK_BS) >> PAGE_SHIFT);
	if (!page->private) {
		printk(KERN_ERR "rmap_remove: %p %llx 0->BUG\n", spte, *spte);
		BUG();
	} else if (!(page->private & 1)) {
		rmap_printk_bs("rmap_remove: %p %llx 1->0\n", spte, *spte);
		if ((u64 *)page->private != spte) {
			printk(KERN_ERR "rmap_remove: %p %llx 1->BUG\n",
					spte, *spte);
			BUG();
		}
		page->private = 0;
	} else {
		rmap_printk_bs("rmap_remove: %p %llx many->many\n", 
								spte, *spte);
		desc = (struct kvm_rmap_desc_bs *)(page->private & ~1ul);
		prev_desc = NULL;
		while (desc) {
			for (i = 0; i < RMAP_EXT_BS && desc->shadow_ptes[i]; 
									++i)
				if (desc->shadow_ptes[i] == spte) {
					rmap_desc_remove_entry_bs(vcpu, page,
							desc, i, prev_desc);
					return;
				}
			prev_desc = desc;
			desc = desc->more;
		}
		BUG();
	}
}

static void kvm_mmu_page_unlink_children_bs(struct kvm_vcpu_bs *vcpu,
						struct kvm_mmu_page_bs *page)
{
	unsigned i;
	u64 *pt;
	u64 ent;

	pt = __va(page->page_hpa);

	if (page->role.level == PT_PAGE_TABLE_LEVEL_BS) {
		for (i = 0; i < PT64_ENT_PER_PAGE_BS; ++i) {
			if (pt[i] & PT_PRESENT_MASK_BS)
				rmap_remove_bs(vcpu, &pt[i]);
			pt[i] = 0;
		}
		kvm_arch_ops_bs->tlb_flush(vcpu);
		return;
	}

	for (i = 0; i < PT64_ENT_PER_PAGE_BS; ++i) {
		ent = pt[i];

		pt[i] = 0;
		if (!ent & PT_PRESENT_MASK_BS)
			continue;
		ent &= PT64_BASE_ADDR_MASK_BS;
		mmu_page_remove_parent_pte_bs(vcpu, 
					page_header_bs(ent), &pt[i]);
	}
}

static int is_empty_shadow_page_bs(hpa_t_bs page_hpa)
{
	u64 *pos;
	u64 *end;

	for (pos = __va(page_hpa), end = pos + PAGE_SIZE / sizeof(u64);
				pos != end; pos++)
		if (*pos != 0) {
			printk(KERN_ERR "%s: %p %llx\n", __FUNCTION__,
					pos, *pos);
			return 0;
		}
	return 1;
}

static void kvm_mmu_free_page_bs(struct kvm_vcpu_bs *vcpu, hpa_t_bs page_hpa)
{
	struct kvm_mmu_page_bs *page_head = page_header_bs(page_hpa);

	ASSERT_BS(is_empty_shadow_page_bs(page_hpa));
	list_del(&page_head->link);
	page_head->page_hpa = page_hpa;
	list_add(&page_head->link, &vcpu->free_pages);
	++vcpu->kvm->n_free_mmu_pages;
}

static void kvm_mmu_zap_page_bs(struct kvm_vcpu_bs *vcpu,
					struct kvm_mmu_page_bs *page)
{
	u64 *parent_pte;

	while (page->multimapped || page->parent_pte) {
		if (!page->multimapped)
			parent_pte = page->parent_pte;
		else {
			struct kvm_pte_chain_bs *chain;

			chain = container_of(page->parent_ptes.first,
						struct kvm_pte_chain_bs, link);
			parent_pte = chain->parent_ptes[0];
		}
		BUG_ON(!parent_pte);
		kvm_mmu_put_page_bs(vcpu, page, parent_pte);
		*parent_pte = 0;
	}
	kvm_mmu_page_unlink_children_bs(vcpu, page);
	if (!page->root_count) {
		hlist_del(&page->hash_link);
		kvm_mmu_free_page_bs(vcpu, page->page_hpa);
	} else {
		list_del(&page->link);
		list_add(&page->link, &vcpu->kvm->active_mmu_pages);
	}
	
}

static void free_mmu_pages_bs(struct kvm_vcpu_bs *vcpu)
{
	struct kvm_mmu_page_bs *page;

	while (!list_empty(&vcpu->kvm->active_mmu_pages)) {
		page = container_of(vcpu->kvm->active_mmu_pages.next,
				struct kvm_mmu_page_bs, link);
		kvm_mmu_zap_page_bs(vcpu, page);
	}
	while (!list_empty(&vcpu->free_pages)) {
		page = list_entry(vcpu->free_pages.next,
					struct kvm_mmu_page_bs, link);
		list_del(&page->link);
		__free_page(pfn_to_page(page->page_hpa >> PAGE_SHIFT));
		page->page_hpa = INVALID_PAGE_BS;
	}
	free_page((unsigned long)vcpu->mmu.pae_root);
}

static void mmu_free_memory_cache_bs(struct kvm_mmu_memory_cache_bs *mc)
{
	while (mc->nobjs)
		kfree(mc->objects[--mc->nobjs]);
}

static void mmu_free_memory_caches_bs(struct kvm_vcpu_bs *vcpu)
{
	mmu_free_memory_cache_bs(&vcpu->mmu_pte_chain_cache);
	mmu_free_memory_cache_bs(&vcpu->mmu_rmap_desc_cache);
}

void kvm_mmu_destroy_bs(struct kvm_vcpu_bs *vcpu)
{
	ASSERT_BS(vcpu);

	destroy_kvm_mmu_bs(vcpu);
	free_mmu_pages_bs(vcpu);
	mmu_free_memory_caches_bs(vcpu);
}

static int alloc_mmu_pages_bs(struct kvm_vcpu_bs *vcpu)
{
	struct page *page;
	int i;

	ASSERT_BS(vcpu);

	for (i = 0; i < KVM_NUM_MMU_PAGES_BS; i++) {
		struct kvm_mmu_page_bs *page_header = &vcpu->page_header_buf[i];

		INIT_LIST_HEAD(&page_header->link);
		if ((page = alloc_page(GFP_KERNEL)) == NULL)
			goto error_1;
		page->private = (unsigned long)page_header;
		page_header->page_hpa = 
				(hpa_t_bs)page_to_pfn(page) << PAGE_SHIFT;
		memset(__va(page_header->page_hpa), 0, PAGE_SIZE);
		list_add(&page_header->link, &vcpu->free_pages);
		++vcpu->kvm->n_free_mmu_pages;
	}

	/*
	 * When emulating 32-bit mode, cr3 is only 32 bits even on X86_64.
	 * Therefore we need to allocate shadow page tables in the first
	 * 4GB of memory, which happens to fit the DMA32 zone.
	 */
	page = alloc_page(GFP_KERNEL | __GFP_DMA32);
	if (!page)
		goto error_1;
	vcpu->mmu.pae_root = page_address(page);
	for (i = 0; i < 4; ++i)
		vcpu->mmu.pae_root[i] = INVALID_PAGE_BS;

	return 0;

error_1:
	free_mmu_pages_bs(vcpu);
	return -ENOMEM;
}

static void nonpaging_new_cr3_bs(struct kvm_vcpu_bs *vcpu)
{
}

static int nonpaging_page_fault_bs(struct kvm_vcpu_bs *vcpu, gva_t_bs gva,
					u32 error_code)
{
	BS_DUP();
	return 0;
}

static 
gpa_t_bs nonpaging_gva_to_gpa_bs(struct kvm_vcpu_bs *vcpu, gva_t_bs vaddr)
{
	return vaddr;
}

static void nonpaging_free_bs(struct kvm_vcpu_bs *vcpu)
{
	BS_DUP();
}

static unsigned kvm_page_table_hashfn_bs(gfn_t_bs gfn)
{
	return gfn;
}

static struct kvm_mmu_page_bs *kvm_mmu_alloc_page_bs(struct kvm_vcpu_bs *vcpu,
							u64 *parent_pte)
{
	struct kvm_mmu_page_bs *page;

	if (list_empty(&vcpu->free_pages))
		return NULL;

	page = list_entry(vcpu->free_pages.next, struct kvm_mmu_page_bs, link);
	list_del(&page->link);
	list_add(&page->link, &vcpu->kvm->active_mmu_pages);
	ASSERT_BS(is_empty_shadow_page_bs(page->page_hpa));
	page->slot_bitmap = 0;
	page->global = 1;
	page->multimapped = 0;
	page->parent_pte = parent_pte;
	--vcpu->kvm->n_free_mmu_pages;
	return page;
}

static struct kvm_mmu_page_bs *kvm_mmu_get_page_bs(struct kvm_vcpu_bs *vcpu,
			gfn_t_bs gfn, gva_t_bs gaddr, unsigned level,
			int metaphysical, u64 *parent_pte)
{
	union kvm_mmu_page_role_bs role;
	unsigned index;
	unsigned quadrant;
	struct hlist_head *bucket;
	struct kvm_mmu_page_bs *page;
	struct hlist_node *node;

	role.word = 0;
	role.glevels = vcpu->mmu.root_level;
	role.level = level;
	role.metaphysical = metaphysical;
	if (vcpu->mmu.root_level <= PT32_ROOT_LEVEL_BS) {
		quadrant = gaddr >> (PAGE_SHIFT + (PT64_PT_BITS_BS * level));
		quadrant &= (1 << ((PT32_PT_BITS_BS - 
					PT64_PT_BITS_BS) * level)) - 1;
		role.quadrant = quadrant;
	}
	pgprintk_bs("%s: looking gfn %lx role %x\n", __FUNCTION__,
				gfn, role.word);
	index = kvm_page_table_hashfn_bs(gfn) & KVM_NUM_MMU_PAGES_BS;
	bucket = &vcpu->kvm->mmu_page_hash[index];
	hlist_for_each_entry_bs(page, node, bucket, hash_link) {
		if (page->gfn == gfn && page->role.word == role.word) {
			BS_DUP();
			return page;
		}
	}
	page = kvm_mmu_alloc_page_bs(vcpu, parent_pte);
	if (!page)
		return page;
	pgprintk_bs("%s: adding gfn %lx role %x\n", __func__, gfn, role.word);
	page->gfn = gfn;
	page->role = role;
	hlist_add_head(&page->hash_link, bucket);
	if (!metaphysical)
		BS_DUP();
	return page;
}

static void mmu_alloc_roots_bs(struct kvm_vcpu_bs *vcpu)
{
	int i;
	gfn_t_bs root_gfn;
	struct kvm_mmu_page_bs *page;

	root_gfn = vcpu->cr3 >> PAGE_SHIFT;

	for (i = 0; i < 4; ++i) {
		hpa_t_bs root = vcpu->mmu.pae_root[i];

		ASSERT_BS(!VALID_PAGE_BS(root));
		if (vcpu->mmu.root_level == PT32E_ROOT_LEVEL_BS)
			root_gfn = vcpu->pdptrs[i] >> PAGE_SHIFT;
		else if (vcpu->mmu.root_level == 0)
			root_gfn = 0;
		page = kvm_mmu_get_page_bs(vcpu, root_gfn, i << 30,
				PT32_ROOT_LEVEL_BS, !is_paging_bs(vcpu),
				NULL);
		root = page->page_hpa;
		++page->root_count;
		vcpu->mmu.pae_root[i] = root | PT_PRESENT_MASK_BS;
	}
	vcpu->mmu.root_hpa = __pa(vcpu->mmu.pae_root);
}

static int nonpaging_init_context_bs(struct kvm_vcpu_bs *vcpu)
{
	struct kvm_mmu_bs *context = &vcpu->mmu;

	context->new_cr3 = nonpaging_new_cr3_bs;
	context->page_fault = nonpaging_page_fault_bs;
	context->gva_to_gpa = nonpaging_gva_to_gpa_bs;
	context->free = nonpaging_free_bs;
	context->root_level = 0;
	context->shadow_root_level = PT32E_ROOT_LEVEL_BS;
	mmu_alloc_roots_bs(vcpu);
	ASSERT_BS(VALID_PAGE_BS(context->root_hpa));
	kvm_arch_ops_bs->set_cr3(vcpu, context->root_hpa);
	return 0;
}

static int init_kvm_mmu_bs(struct kvm_vcpu_bs *vcpu)
{
	ASSERT_BS(vcpu);
	ASSERT_BS(!VALID_PAGE_BS(vcpu->mmu.root_hpa));

	if (!is_paging_bs(vcpu)) {
		return nonpaging_init_context_bs(vcpu);
	} else if (is_long_mode_bs(vcpu)) {
		BS_DUP();
		return 0;
	} else if (is_pae_bs(vcpu)) {
		BS_DUP();
		return 0;
	} else {
		BS_DUP();
		return 0;
	}
}

int kvm_mmu_create_bs(struct kvm_vcpu_bs *vcpu)
{
	ASSERT_BS(vcpu);
	ASSERT_BS(!VALID_PAGE_BS(vcpu->mmu.root_hpa));
	ASSERT_BS(list_empty(&vcpu->free_pages));

	return alloc_mmu_pages_bs(vcpu);
}

int kvm_mmu_setup_bs(struct kvm_vcpu_bs *vcpu)
{
	ASSERT_BS(vcpu);
	ASSERT_BS(!VALID_PAGE_BS(vcpu->mmu.root_hpa));
	ASSERT_BS(!list_empty(&vcpu->free_pages));

	return init_kvm_mmu_bs(vcpu);
}
