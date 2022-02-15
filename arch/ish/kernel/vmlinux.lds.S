#include <asm-generic/vmlinux.lds.h>
#include <asm/page.h>
#include <asm/cache.h>
#include <asm/thread_info.h>

jiffies = jiffies_64;

VERSION {
  {
    local: *;
  };
}

SECTIONS
{
	. = SIZEOF_HEADERS;

	_text = .;
	__init_begin = .;
	HEAD_TEXT_SECTION
	INIT_TEXT_SECTION(PAGE_SIZE)
	INIT_DATA_SECTION(16)
	PERCPU_SECTION(L1_CACHE_BYTES)
	__init_end = .;

	.hash           : { *(.hash) }
	.gnu.hash       : { *(.gnu.hash) }
	.dynsym         : { *(.dynsym) }
	.dynstr         : { *(.dynstr) }
	.gnu.version    : { *(.gnu.version) }
	.gnu.version_d  : { *(.gnu.version_d) }
	.gnu.version_r  : { *(.gnu.version_r) }
	.rel.init       : { *(.rel.init) }
	.rela.init      : { *(.rela.init) }
	.rel.text       : { *(.rel.text .rel.text.* .rel.gnu.linkonce.t.*) }
	.rela.text      : { *(.rela.text .rela.text.* .rela.gnu.linkonce.t.*) }
	.rel.fini       : { *(.rel.fini) }
	.rela.fini      : { *(.rela.fini) }
	.rel.rodata     : { *(.rel.rodata .rel.rodata.* .rel.gnu.linkonce.r.*) }
	.rela.rodata    : { *(.rela.rodata .rela.rodata.* .rela.gnu.linkonce.r.*) }
	.rel.data       : { *(.rel.data .rel.data.* .rel.gnu.linkonce.d.*) }
	.rela.data      : { *(.rela.data .rela.data.* .rela.gnu.linkonce.d.*) }
	.rel.tdata      : { *(.rel.tdata .rel.tdata.* .rel.gnu.linkonce.td.*) }
	.rela.tdata     : { *(.rela.tdata .rela.tdata.* .rela.gnu.linkonce.td.*) }
	.rel.tbss       : { *(.rel.tbss .rel.tbss.* .rel.gnu.linkonce.tb.*) }
	.rela.tbss      : { *(.rela.tbss .rela.tbss.* .rela.gnu.linkonce.tb.*) }
	.rel.ctors      : { *(.rel.ctors) }
	.rela.ctors     : { *(.rela.ctors) }
	.rel.dtors      : { *(.rel.dtors) }
	.rela.dtors     : { *(.rela.dtors) }
	.rel.got        : { *(.rel.got) }
	.rela.got       : { *(.rela.got) }
	.rel.bss        : { *(.rel.bss .rel.bss.* .rel.gnu.linkonce.b.*) }
	.rela.bss       : { *(.rela.bss .rela.bss.* .rela.gnu.linkonce.b.*) }
	.rel.plt : {
		*(.rel.plt)
		PROVIDE_HIDDEN(__rel_iplt_start = .);
		*(.rel.iplt)
		PROVIDE_HIDDEN(__rel_iplt_end = .);
	}
	.rela.plt : {
		*(.rela.plt)
		PROVIDE_HIDDEN(__rela_iplt_start = .);
		*(.rela.iplt)
		PROVIDE_HIDDEN(__rela_iplt_end = .);
	}
	_stext = .;
	.text : {
		TEXT_TEXT
		SCHED_TEXT
		CPUIDLE_TEXT
		LOCK_TEXT
	}
	_etext = .;

	_sdata = .;
	RO_DATA(PAGE_SIZE)
	RW_DATA(16, PAGE_SIZE, THREAD_SIZE)
	_edata = .;

	EXCEPTION_TABLE(16)

	.init_array : {
		__init_array_start = .;
		*(.init_array)
		__init_array_end = .;
	}

	BSS_SECTION(0, 0, 0)
	_end = .;

	STABS_DEBUG
	DWARF_DEBUG

	DISCARDS
}
