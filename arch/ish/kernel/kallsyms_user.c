#if defined(__ELF__)
#define USE_SYMTAB 1
#else
#define USE_SYMTAB 0
#endif

#define _GNU_SOURCE
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#if USE_SYMTAB
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <user/user.h>
#define KSYM_NAME_LEN 128

#if USE_SYMTAB
/* We have to mmap the file manually because debugger and static linker info
 * such as symtab and strtab is not mapped by the program headers. */
static void *mmap_image(Dl_info *info)
{
	int fd;
	struct stat statbuf;
	void *mapping;
	/* mmap is slow, don't call it too much. */
	static struct mmap_cache {
		void *base;
		void *mapping;
	} cache[10] = {};
	struct mmap_cache *c = NULL;
	int i;

	for (i = 0; i < sizeof(cache)/sizeof(cache[0]); i++) {
		if (cache[i].base == NULL) {
			c = &cache[i];
			break;
		}
		if (cache[i].base == info->dli_fbase)
			return cache[i].mapping;
	}
	if (c == NULL)
		return NULL;

	c->base = info->dli_fbase;
	fd = open(info->dli_fname, O_RDONLY);
	if (fd < 0) {
		printk("failed to open %s for symbolizing: %s\n", info->dli_fname, strerror(errno));
		return NULL;
	}
	fstat(fd, &statbuf);
	c->mapping = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (c->mapping == NULL) {
		printk("failed to mmap %s for symbolizing: %s\n", info->dli_fname, strerror(errno));
	}
	close(fd);
	return c->mapping;
}

static int elf_symtab_lookup(unsigned long addr, Dl_info *info, unsigned long *symbolsize)
{
	unsigned long offset = (void *) addr - info->dli_fbase;
	void *base = mmap_image(info);

	const ElfW(Ehdr) *hdr = base;
	const ElfW(Shdr) *sects = base + hdr->e_shoff;
	const ElfW(Sym) *symtab = NULL;
	const ElfW(Sym) *sym = NULL;
	size_t symtab_size;
	const char *strtab = NULL;
	size_t i;

	for (i = 0; i < hdr->e_shnum; i++) {
		switch (sects[i].sh_type) {
		case SHT_SYMTAB:
			symtab = base + sects[i].sh_offset;
			symtab_size = sects[i].sh_size / sizeof(*symtab);
			strtab = base + sects[sects[i].sh_link].sh_offset;
			break;
		}
	}

	for (i = 0; i < symtab_size; i++) {
		/* Skip if symbol starts after our pointer */
		if (symtab[i].st_value > offset)
			continue;
		/* If the size can be trusted, skip if the symbol ends before our pointer */
		if (symtab[i].st_shndx != SHN_UNDEF && symtab[i].st_size != 0)
			if (symtab[i].st_value + symtab[i].st_size <= offset)
				continue;
		/* Take the symbol with the closest start to our pointer */
		if (sym == NULL || sym->st_value < symtab[i].st_value)
			sym = &symtab[i];
	}

	if (sym == NULL)
		return -1;
	info->dli_saddr = info->dli_fbase + sym->st_value;
	info->dli_sname = &strtab[sym->st_name];
	if (symbolsize)
		*symbolsize = sym->st_size;
	return 0;
}
#else
static int elf_symtab_lookup(unsigned long addr, Dl_info *info)
{
	return -1;
}
#endif

const char *kallsyms_lookup(unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf)
{
	const char *module;
	Dl_info info;
	if (dladdr((const void *) addr, &info) == 0)
		return NULL;
	if (info.dli_fbase == NULL)
		return NULL;

	if (info.dli_sname == NULL) {
		if (elf_symtab_lookup(addr, &info, symbolsize) != 0)
			return NULL;
	} else {
		/* lol no one cares */
		if (symbolsize)
			*symbolsize = 0;
	}

	module = strrchr(info.dli_fname, '/');
	if (module == NULL) {
		module = info.dli_fname;
	} else {
		module++;
	}
	if (modname)
		*modname = (char *) module;

	if (offset)
		*offset = addr - (unsigned long) info.dli_saddr;

	strncpy(namebuf, info.dli_sname, KSYM_NAME_LEN);
	namebuf[KSYM_NAME_LEN - 1] = '\0';
	return namebuf;
}
