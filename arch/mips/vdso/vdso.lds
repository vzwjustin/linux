OUTPUT_FORMAT("elf32-tradlittlemips", "elf32-tradbigmips", "elf32-tradlittlemips")
OUTPUT_ARCH(mips)
SECTIONS
{
 PROVIDE(vdso_u_data = . - 4 * (1 << 14)); PROVIDE(vdso_u_time_data = vdso_u_data);
 . = SIZEOF_HEADERS;
 .mips_abiflags : { *(.mips_abiflags) } :text :abiflags
 .reginfo : { *(.reginfo) } :text :reginfo
 .hash : { *(.hash) } :text
 .gnu.hash : { *(.gnu.hash) }
 .dynsym : { *(.dynsym) }
 .dynstr : { *(.dynstr) }
 .gnu.version : { *(.gnu.version) }
 .gnu.version_d : { *(.gnu.version_d) }
 .gnu.version_r : { *(.gnu.version_r) }
 .note : { *(.note.*) } :text :note
 .text : { *(.text*) } :text
 PROVIDE (__etext = .);
 PROVIDE (_etext = .);
 PROVIDE (etext = .);
 .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
 .eh_frame : { KEEP (*(.eh_frame)) } :text
 .dynamic : { *(.dynamic) } :text :dynamic
 .rodata : { *(.rodata*) } :text
 _end = .;
 PROVIDE(end = .);
 /DISCARD/ : {
  *(.MIPS.abiflags)
  *(.gnu.attributes)
  *(.note.GNU-stack)
  *(.data .data.* .gnu.linkonce.d.* .sdata*)
  *(.bss .sbss .dynbss .dynsbss)
 }
}
PHDRS
{
 abiflags 0x70000003;
 reginfo 0x70000000;
 text PT_LOAD FLAGS(5) FILEHDR PHDRS;
 dynamic PT_DYNAMIC FLAGS(4);
 note PT_NOTE FLAGS(4);
 eh_frame_hdr PT_GNU_EH_FRAME;
}
VERSION
{
 LINUX_2.6 {
 global:
  __vdso_clock_gettime;
  __vdso_gettimeofday;
  __vdso_clock_getres;
  __vdso_clock_gettime64;
  __vdso_clock_getres_time64;
 local: *;
 };
}
