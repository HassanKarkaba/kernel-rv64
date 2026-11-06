.section .text.entry
.globl _start
_start:
    csrw sie, zero
    csrw sscratch, zero
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la t0, __bss_start
    la t1, __bss_end
1:  bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:  la sp, BOOT_STACK
    li t0, 524288
    add sp, sp, t0
    tail kernel_main
