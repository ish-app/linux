ifdef CONFIG_HOST_DARWIN
	extra-y += sections.o
endif
ifdef CONFIG_HOST_LINUX
	extra-y += vmlinux.lds
endif

obj-y := cpu.o irq.o mem.o reboot.o setup.o signal.o time.o trap.o process.o \
	ptrace.o uaccess.o syscalls.o tls.o stacktrace.o

obj-y += syscalls_user.o irq_user.o time_user.o poll_user.o threads_user.o setup_user.o random_user.o
obj-y += setjmp.o

obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
obj-$(CONFIG_SMP) += smp.o
obj-$(CONFIG_ARCH_KALLSYMS) += kallsyms.o kallsyms_user.o

include arch/um/scripts/Makefile.rules

obj-y += stubs.o
