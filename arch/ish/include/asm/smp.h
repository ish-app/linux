#ifndef __ISH_ASM_SMP_H
#define __ISH_ASM_SMP_H

#include <linux/cpumask.h>

#define raw_smp_processor_id() (current_thread_info()->cpu)

void arch_send_call_function_single_ipi(int cpu);
void arch_send_call_function_ipi_mask(const struct cpumask *mask);

#endif
