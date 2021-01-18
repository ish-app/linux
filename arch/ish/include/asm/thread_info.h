#ifndef __ASM_ISH_THREAD_INFO_H
#define __ASM_ISH_THREAD_INFO_H

#include <asm/types.h>
#include <asm/processor.h>

#define THREAD_SIZE_ORDER (4)
#define THREAD_SIZE (PAGE_SIZE << (THREAD_SIZE_ORDER))

// TODO is all this necessary?
struct thread_info {
	unsigned long		flags;		/* low level flags */
	int			preempt_count;	/* 0 => preemptable, <0 => BUG */
	mm_segment_t		addr_limit;	/* thread address space */
};
#define INIT_THREAD_INFO(tsk) \
{ \
	.addr_limit	= KERNEL_DS, \
}

#define TIF_SYSCALL_TRACE	0	/* syscall trace active */
#define TIF_SIGPENDING		1	/* signal pending */
#define TIF_NEED_RESCHED	2	/* rescheduling necessary */
#define TIF_MEMDIE		5	/* is terminating due to OOM killer */

#endif
