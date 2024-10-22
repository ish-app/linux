#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
int main() {
	Dl_info info;
	ElfW(Sym) *sym;
	int err = dladdr1(main, &info, (void **) &sym, RTLD_DL_SYMENT);
	printf("%d %s %s %s %p\n", err, dlerror(), info.dli_fname, info.dli_sname, sym);
}
