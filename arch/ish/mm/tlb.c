#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>

extern void emu_flush_tlb_local(struct emu_mm *mm, unsigned long start, unsigned long end);

struct flush_tlb_args {
	struct emu_mm *mm;
	unsigned long start;
	unsigned long end;
};
static void __call_emu_flush_tlb(void *info)
{
	struct flush_tlb_args *args = info;
	emu_flush_tlb_local(args->mm, args->start, args->end);
}
static void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct flush_tlb_args args = {&mm->context.emu_mm, start, end};
	on_each_cpu_mask(mm_cpumask(mm), __call_emu_flush_tlb, &args, true);
}

void flush_tlb_mm(struct mm_struct *mm)
{
	flush_tlb_mm_range(mm, 0, TASK_SIZE);
}
void flush_tlb_range(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	flush_tlb_mm_range(vma->vm_mm, start, end);
}
void flush_tlb_page(struct vm_area_struct *vma, unsigned long address)
{
	flush_tlb_range(vma, address, address + 1);
}
