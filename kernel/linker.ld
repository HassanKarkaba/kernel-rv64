OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
  . = 0x80200000;
  __kernel_start = .;
  .text : ALIGN(4096) { KEEP(*(.text.entry)) *(.text .text.*) }
  . = ALIGN(4096); __text_end = .;
  .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
  . = ALIGN(4096); __rodata_end = .;
  .data : ALIGN(4096) { PROVIDE(__global_pointer$ = . + 0x800); *(.data .data.*) *(.sdata .sdata.*) }
  . = ALIGN(4096);
  .bss (NOLOAD) : { __bss_start = .; *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) __bss_end = .; }
  . = ALIGN(4096); __kernel_end = .;
  /DISCARD/ : { *(.eh_frame .eh_frame_hdr) }
}
