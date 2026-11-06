OUTPUT_ARCH(riscv)
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x10000;
    .text : ALIGN(4096) { KEEP(*(.text.entry)) *(.text .text.*) } :text
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) *(.srodata .srodata.*) } :rodata
    .data : ALIGN(4096) { PROVIDE(__global_pointer$ = . + 0x800); *(.data .data.*) *(.sdata .sdata.*) } :data
    .bss : ALIGN(16) { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) . = MAX(., ADDR(.data) + 1); } :data
    /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.riscv.attributes*) }
}
