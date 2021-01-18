#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/signal_types.h>
#include <asm/errno.h>
#include <asm/ptrace.h>
#include <asm/sighandling.h>
#include <asm/signal.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

extern int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
			compat_sigset_t *set, struct pt_regs *regs);
extern int ia32_setup_frame(int sig, struct ksignal *ksig,
		     compat_sigset_t *set, struct pt_regs *regs);

static void handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
	int err;
	sigset_t *set;
	compat_sigset_t *cset;

	/* Did we come from a system call? */
	if (syscall_get_nr(current, regs) >= 0) {
		/* If so, check system call restarting.. */
		switch (syscall_get_error(current, regs)) {
		case -ERESTART_RESTARTBLOCK:
		case -ERESTARTNOHAND:
			regs->ax = -EINTR;
			break;

		case -ERESTARTSYS:
			if (!(ksig->ka.sa.sa_flags & SA_RESTART)) {
				regs->ax = -EINTR;
				break;
			}
		/* fallthrough */
		case -ERESTARTNOINTR:
			regs->ax = regs->orig_ax;
			regs->ip -= 2;
			break;
		}
	}

	rseq_signal_deliver(ksig, regs);

	set = sigmask_to_save();
	cset = (compat_sigset_t *) set;

	if (ksig->ka.sa.sa_flags & SA_SIGINFO)
		err = ia32_setup_rt_frame(ksig->sig, ksig, cset, regs);
	else
		err = ia32_setup_frame(ksig->sig, ksig, cset, regs);
	signal_setup_done(err, ksig, 0 /* TODO @ptrace single_step */);
}

void do_signal(struct pt_regs *regs)
{
	struct ksignal ksig;

	int pending = test_thread_flag(TIF_SIGPENDING);

	if (get_signal(&ksig)) {
		if (!pending)
			printk("got a signal and yet nothing is pending!");
		handle_signal(&ksig, regs);
		return;
	}

	/* Did we come from a system call? */
	if (syscall_get_nr(current, regs) >= 0) {
		/* Restart the system call - no handlers present */
		switch (syscall_get_error(current, regs)) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs->ax = regs->orig_ax;
			regs->ip -= 2;
			break;

		case -ERESTART_RESTARTBLOCK:
			regs->ax = __NR_restart_syscall;
			regs->ip -= 2;
			break;
		}
	}

	/*
	 * If there's no signal to deliver, we just put the saved sigmask
	 * back.
	 */
	restore_saved_sigmask();
}

void signal_fault(struct pt_regs *regs, void __user *frame, char *where)
{
	struct task_struct *me = current;

	if (show_unhandled_signals && printk_ratelimit()) {
		printk("%s"
		       "%s[%d] bad frame in %s frame:%p ip:%lx sp:%lx orax:%lx",
		       task_pid_nr(current) > 1 ? KERN_INFO : KERN_EMERG,
		       me->comm, me->pid, where, frame,
		       regs->ip, regs->sp, regs->orig_ax);
		print_vma_addr(KERN_CONT " in ", regs->ip);
		pr_cont("\n");
	}

	force_sig(SIGSEGV);
}

