#ifndef __ASM_ISH_PAGE_H
#define __ASM_ISH_PAGE_H

#define PAGE_SHIFT	12
#ifdef __ASSEMBLY__
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#else
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK	(~(PAGE_SIZE-1))

typedef struct {
	unsigned long pte;
} pte_t;
typedef struct {
	unsigned long pgd;
} pgd_t;
typedef struct {
	unsigned long pgprot;
} pgprot_t;
typedef struct page *pgtable_t;

#define pte_val(x)	((x).pte)
#define __pte(x)	((pte_t) { (x) })
#define pgd_val(x)	((x).pgd)
#define __pgd(x)	((pgd_t) { (x) })
#define pgprot_val(x)	((x).pgprot)
#define __pgprot(x)	((pgprot_t) { (x) })

extern unsigned long ish_phys_base;
#define __pa(virt)	((unsigned long) (virt) - ish_phys_base)
#define __va(phys)	((void *) ((unsigned long) (phys) + ish_phys_base))
#define PAGE_OFFSET (ish_phys_base)

#define pfn_valid(pfn)		((pfn) < max_mapnr)
#define phys_to_pfn(p)		((p) >> PAGE_SHIFT)
#define virt_to_page(virt)	pfn_to_page(phys_to_pfn(__pa(virt)))
#define page_to_phys(page)	(page_to_pfn(page) << PAGE_SHIFT)
#define virt_addr_valid(virt)	pfn_valid(phys_to_pfn(__pa(virt)))

#define copy_page(to, from)	memcpy((void *) (to), (void *) (from), PAGE_SIZE)
#define clear_page(page)	memset((void *) (page), 0, PAGE_SIZE)
// TODO: probably wrong
#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

#define VMALLOC_START 0x10000
#define VMALLOC_END (PAGE_OFFSET - 1)

#include <asm-generic/getorder.h>

#endif
