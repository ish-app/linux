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

#include <asm/unistd.h>

void show_regs(struct pt_regs *regs)
{
	printk("<regs would go here>\n");
}

static void show_stack_frame(void *addr, const char *loglvl)
{
	char buf[128];
	struct sym_info info;
	if (lookup_symbol(addr, &info)) {
		snprintf(buf, sizeof(buf), "[%px] %s`%s+%d", addr, info.module, info.symbol, addr - info.symbol_addr);
	} else {
		snprintf(buf, sizeof(buf), "%px", addr);
	}
	printk("%s %s\n", loglvl, buf);
}

struct stackframe {
	struct stackframe *fp;
	void *ret;
};

void show_stack(struct task_struct *task, unsigned long *stack,
		const char *loglvl)
{
	struct stackframe *frame;
	void *pc;
	void *stack_low, *stack_high;

	if (task == NULL)
		task = current;
	stack_low = task_stack_page(task);
	stack_high = stack_low + THREAD_SIZE;

	if (task == current) {
		frame = __builtin_frame_address(0);
		pc = show_stack;
	} else {
		frame = (void *) task->thread.kernel_regs->rbp;
		pc = (void *) KSTK_EIP(task);
	}

	pr_cont("Call Trace:\n");
	for (;;) {
		if (pc)
			show_stack_frame(pc, loglvl);
		if ((void *) frame < stack_low || (void *) frame >= stack_high)
			break;
		pc = frame->ret;
		frame = frame->fp;
	}
	// TODO: make %pS work
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

static void __user_thread(void)
{
	struct pt_regs *regs = current_pt_regs();

	for (;;) {
		int interrupt;
		ktime_t start;
		unsigned long run_time_us;

		start = ktime_get();
		interrupt = emu_run_to_interrupt(&current->thread.emu, current_pt_regs());
		run_time_us = ktime_to_us(ktime_sub(ktime_get(), start));
		if (run_time_us > 50000)
			printk(KERN_WARNING "emulator ran for %luus!", run_time_us);
		regs->trap_nr = interrupt;
		regs->orig_ax = regs->ax;

		if (interrupt == 6) {
			/* undefined instruction */
			show_signal(current, "undefined instruction", regs->ip);
			force_sig_fault(SIGILL, SI_KERNEL, (void __user *) regs->ip);
		} else if (interrupt == 13 || interrupt == 14) {
			/* GPF or page fault */
			int code;
			int err = handle_page_fault(regs->cr2, regs->error_code & 2, &code);
			if (err != 0) {
				show_signal(current, "page fault", regs->cr2);
				force_sig_fault(SIGSEGV, code, (void __user *) regs->cr2);
			}
		} else if (interrupt == 0x80) {
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
			trace_syscall_exit(regs);
		} else if (interrupt == 0x20) {
			/* timer */
		} else {
			show_signal(current, "mysterious interrupt", interrupt);
			force_sig_fault(SIGSEGV, SI_KERNEL, 0);
		}

signal:
		if (need_resched())
			schedule();
		do_signal(regs);
	}
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

int copy_thread_tls(unsigned long clone_flags, unsigned long usp,
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
	KSTK_ESP(p) = (unsigned long) task_stack_page(p) + THREAD_SIZE - sizeof(void *);
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

	current = to;
	last = (void *) ksetjmp(from->thread.kernel_regs);
	if (last == NULL)
		klongjmp(to->thread.kernel_regs, (unsigned long) from);
	/* switch_mm(last->mm, current->mm, current); */
	return last;
}

void arch_cpu_idle(void)
{
	local_irq_enable();
	host_pause();
}

__thread struct task_struct *current;

unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)];
