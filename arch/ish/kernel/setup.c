#include <asm/page.h>
#include <linux/build_bug.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/sched/task.h>
#include <linux/start_kernel.h>
#include <user/user.h>
#include <user/errno.h>

char *empty_zero_page;

void __init setup_arch(char **cmdline_p)
{
	unsigned long zone_pfns[MAX_NR_ZONES] = {};

	*cmdline_p = boot_command_line;
	parse_early_param();

	ish_phys_size = 0x10000000;
	ish_phys_base = (unsigned long) host_mmap((void *) 0x200000000, ish_phys_size);
	memblock_add(__pa(ish_phys_base), ish_phys_size);

	zone_pfns[ZONE_NORMAL] = ish_phys_size >> PAGE_SHIFT;
	free_area_init(zone_pfns);

	empty_zero_page = memblock_alloc_low(PAGE_SIZE, PAGE_SIZE);

	min_low_pfn = 0;
	max_low_pfn = ish_phys_size >> PAGE_SHIFT;
	max_mapnr = max_pfn = max_low_pfn;
	
	/* TODO @smp: do this for each kernel thread */
	host_block_sigpipe();
}


void run_kernel(void)
{
	current = &init_task;
	start_kernel();
}

#ifdef CONFIG_ISH_MAIN
int main(int argc, const char *argv[])
{
	int i;
	for (i = 1; i < argc; i++) {
		if (i > 1)
			strcat(boot_command_line, " ");
		strcat(boot_command_line, argv[i]);
	}
	run_kernel();
	return 0;
}
#endif

// I see no better place to put this
#define CHECK_ERRNO(name, val) \
	static_assert(name == val);
ERRNOS(CHECK_ERRNO)
#undef CHECK_ERRNO
