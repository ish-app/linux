#ifndef __ISH_EXEC_H
#define __ISH_EXEC_H

struct emu;
struct emu_mm;
struct pt_regs;

extern int emu_run_to_interrupt(struct emu *emu, struct pt_regs *regs);
extern void emu_poke_cpu(int cpu);

extern void emu_mmu_init(struct emu_mm *mm);
extern void emu_mmu_destroy(struct emu_mm *mm);
extern void emu_switch_mm(struct emu *emu, struct emu_mm *mm);

#endif
