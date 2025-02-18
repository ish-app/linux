#include <linux/kallsyms.h>
#include <linux/moduleparam.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <asm/ldt.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <emu/exec.h>
#include <user/user.h>
#include "threads_user.h"
#include "irq_user.h"

#include <asm/unistd.h>

void show_regs(struct pt_regs *regs)
{
	printk("<regs would go here>\n");
}

void start_thread(struct pt_regs *regs, unsigned long eip, unsigned long esp)
{
	regs->ip = eip;
	regs->sp = esp;
}
EXPORT_SYMBOL(start_thread);
void flush_thread(void)
{
}

/* TODO put this in a header */
extern int handle_page_fault(unsigned long address, int is_write, int *code_out);

int show_unhandled_signals = 1; /* TODO this may not be the place */
static void show_signal(struct task_struct *task, const char *desc, unsigned long addr) {
	if (show_unhandled_signals) {
		struct pt_regs *regs = task_pt_regs(task);
		printk("%s[%d] %s addr:%lx ip:%lx sp:%lx\n", task->comm,
		       task_pid_nr(task), desc, addr, regs->ip, regs->sp);
	}
}

struct pt_regs *emu_pt_regs(struct emu *emu)
{
	return &container_of(emu, struct thread_struct, emu)->regs;
}

static bool log_syscalls;
core_param(log_syscalls, log_syscalls, bool, 0644);

void handle_cpu_trap(struct emu *emu)
{
	struct pt_regs *regs = emu_pt_regs(emu);
	unsigned long run_time_us;

	run_time_us = ktime_to_us(ktime_sub(ktime_get(), current->thread.last_trap_time));
	if (run_time_us > 50000)
		pr_warn("emulator ran for %luus!", run_time_us);

	check_irqs();

	regs->orig_ax = regs->ax;
	if (regs->trap_nr == 6) {
		/* undefined instruction */
		char buf[16];
		show_signal(current, "invalid opcode", regs->ip);
		if (copy_from_user_nofault(buf, (void * __user) regs->ip, sizeof(buf)) == 0)
			printk("%s[%d] invalid code: %16ph\n", current->comm, task_pid_nr(current), buf);
		force_sig_fault(SIGILL, SI_KERNEL, (void __user *) regs->ip);
	} else if (regs->trap_nr == 13 || regs->trap_nr == 14) {
		/* GPF or page fault */
		int code;
		int err = handle_page_fault(regs->cr2, regs->error_code & 2, &code);
		if (err != 0) {
			show_signal(current, "page fault", regs->cr2);
			force_sig_fault(SIGSEGV, code, (void __user *) regs->cr2);
		}
	} else if (regs->trap_nr == 3) {
		/* int3 */
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->ip);
	} else if (regs->trap_nr == 0x80) {
		/* syscall */
		unsigned long (*syscall)(unsigned long, unsigned long,
					 unsigned long, unsigned long,
					 unsigned long, unsigned long);

		if (regs->orig_ax > NR_syscalls) {
			show_signal(current, "syscall out of range", regs->orig_ax);
			force_sig_fault(SIGSYS, SI_KERNEL, 0);
			goto signal;
		}
		syscall = sys_call_table[regs->orig_ax];

		if (trace_syscall_enter(regs))
			goto signal;
		regs->ax = syscall(regs->bx, regs->cx, regs->dx,
				   regs->si, regs->di, regs->bp);
		if (log_syscalls) {
			printk("%s[%d] syscall %d(%#x, %#x, %#x) -> %d\n",
			       current->comm, current->pid,
			       regs->orig_ax, regs->bx, regs->cx,
			       regs->dx, regs->ax);
		}
		trace_syscall_exit(regs);
	} else if (regs->trap_nr == 0x20) {
		/* timer */
	} else {
		show_signal(current, "mysterious interrupt", regs->trap_nr);
		force_sig_fault(SIGSEGV, SI_KERNEL, 0);
	}

signal:
	if (need_resched())
		schedule();
	do_signal(regs);

	current->thread.last_trap_time = ktime_get();
}

static void __user_thread(void)
{
	emu_run(&current->thread.emu);
}

static void __kernel_thread(struct task_struct *last)
{
	schedule_tail(last);
	if (current->thread.request.func)
		current->thread.request.func(current->thread.request.arg);
	__user_thread();
}

/* TODO put this in a header */
int do_set_thread_area(struct task_struct *task, struct user_desc __user *u_info);

int copy_thread(unsigned long clone_flags, unsigned long usp,
		unsigned long arg, struct task_struct *p, unsigned long tls)
{
	*task_pt_regs(p) = *current_pt_regs();
	task_pt_regs(p)->ax = 0;
	if (clone_flags & CLONE_SETTLS) {
		int err = do_set_thread_area(p, (struct user_desc __user *) tls);
		if (err < 0)
			return err;
	}
	if (usp) {
		task_pt_regs(p)->sp = usp;
	}
	if (p->thread.emu.ctx != NULL) {
		emu_finish_fork(&p->thread.emu);
	}

	KSTK_ESP(p) = (unsigned long) task_stack_page(p) + THREAD_SIZE - sizeof(void *);
#ifdef __aarch64__
	// AAPCS requires that that stack is quadword aligned.
	KSTK_ESP(p) &= ~0xf;
#endif
	KSTK_EIP(p) = (unsigned long) __kernel_thread;
	p->thread.request.func = NULL;
	if (unlikely(p->flags & PF_KTHREAD)) {
		p->thread.request.func = (void (*)(void *)) usp;
		p->thread.request.arg = (void (*)(void *)) arg;
	}
	return 0;
}

void *__switch_to(struct task_struct *from, struct task_struct *to)
{
	struct task_struct *last;

	BUG_ON(!from);
	__set_current(to);
	last = (void *) ksetjmp(from->thread.kernel_regs);
	if (last == NULL)
		klongjmp(to->thread.kernel_regs, (unsigned long) from);
	/* switch_mm(last->mm, current->mm, current); */
	return last;
}

void release_thread(struct task_struct *task) {
	emu_destroy(&task->thread.emu);
}

unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)];
