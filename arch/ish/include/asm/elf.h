#ifndef __ASM_ISH_ELF_H
#define __ASM_ISH_ELF_H

/* TODO: don't hard code ABIs like this? it sucks? seriously this entire file sucks @abi */

#define ELF_PLATFORM "i686"

typedef u32 elf_greg_t;
/* #define ELF_NGREG (sizeof(struct user_regs_struct) / sizeof(elf_greg_t)) */
#define ELF_NGREG 16
typedef elf_greg_t elf_gregset_t[ELF_NGREG];
/* typedef struct user_i387_struct elf_fpregset_t; */
#define ELF_NFPREG 27
typedef elf_greg_t elf_fpregset_t[ELF_NFPREG];

/*
 * This is used to ensure we don't load something for the wrong architecture.
 */
#define elf_check_arch(x) \
	(((x)->e_machine == EM_386) || ((x)->e_machine == EM_486))

/* SVR4/i386 ABI (pages 3-31, 3-32) says that when the program starts %edx
   contains a pointer to a function which might be registered using `atexit'.
   This provides a mean for the dynamic linker to call DT_FINI functions for
   shared libraries that have been loaded before the code runs.

   A value of 0 tells we have no such handler.

   We might as well make sure everything else is cleared too (except for %esp),
   just to make things more deterministic.
 */
#define ELF_PLAT_INIT(_r, load_addr)		\
	do {					\
	_r->bx = 0; _r->cx = 0; _r->dx = 0;	\
	_r->si = 0; _r->di = 0; _r->bp = 0;	\
	_r->ax = 0;				\
} while (0)

/*
 * These are used to set parameters in the core dumps.
 */
#define ELF_CLASS	ELFCLASS32
#define ELF_DATA	ELFDATA2LSB
#define ELF_ARCH	EM_386

#define ELF_EXEC_PAGESIZE 4096

#define ELF_ET_DYN_BASE		(TASK_SIZE / 3 * 2)
#define ELF_HWCAP		(0) // TODO

#define ARCH_HAS_SETUP_ADDITIONAL_PAGES
struct linux_binprm;
int arch_setup_additional_pages(struct linux_binprm *, int);

#endif
