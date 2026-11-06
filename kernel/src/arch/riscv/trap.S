.section .text
.align 4
.globl trap_entry
trap_entry:
    csrrw sp, sscratch, sp
    bnez sp, 1f
    # Supervisor entry must classify a synchronous fault before touching the
    # faulting stack: its guard may be the reason for this exception. sscratch
    # temporarily preserves t0 while sp is restored for a normal interrupt.
    csrrw t0, sscratch, t0
    mv sp, t0
    csrr t0, scause
    bgez t0, supervisor_fault_stack
    csrrw t0, sscratch, zero
    addi sp, sp, -288
    sd t0, 40(sp)
    addi t0, sp, 288
    sd t0, 16(sp)
    j 2f
1:  addi sp, sp, -288
    sd t0, 40(sp)
    csrr t0, sscratch
    sd t0, 16(sp)
    csrw sscratch, zero
2:  sd zero, 0(sp)
    sd ra, 8(sp)
    sd gp, 24(sp)
    sd tp, 32(sp)
    sd t1, 48(sp)
    sd t2, 56(sp)
    sd s0, 64(sp)
    sd s1, 72(sp)
    sd a0, 80(sp)
    sd a1, 88(sp)
    sd a2, 96(sp)
    sd a3, 104(sp)
    sd a4, 112(sp)
    sd a5, 120(sp)
    sd a6, 128(sp)
    sd a7, 136(sp)
    sd s2, 144(sp)
    sd s3, 152(sp)
    sd s4, 160(sp)
    sd s5, 168(sp)
    sd s6, 176(sp)
    sd s7, 184(sp)
    sd s8, 192(sp)
    sd s9, 200(sp)
    sd s10, 208(sp)
    sd s11, 216(sp)
    sd t3, 224(sp)
    sd t4, 232(sp)
    sd t5, 240(sp)
    sd t6, 248(sp)
    csrr t0, sepc
    sd t0, 256(sp)
    csrr t0, sstatus
    sd t0, 264(sp)
    csrr t0, scause
    sd t0, 272(sp)
    csrr t0, stval
    sd t0, 280(sp)
    # gp is untrusted on a U-mode trap. Save it above, then establish the
    # kernel's global pointer before executing any compiler-generated code.
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    mv a0, sp
    call rust_trap
.globl trap_return
trap_return:
    ld t0, 256(sp)
    csrw sepc, t0
    ld t0, 264(sp)
    csrw sstatus, t0
    andi t0, t0, 256
    bnez t0, 3f
    addi t0, sp, 288
    csrw sscratch, t0
3:  ld ra, 8(sp)
    ld gp, 24(sp)
    ld tp, 32(sp)
    ld t1, 48(sp)
    ld t2, 56(sp)
    ld s0, 64(sp)
    ld s1, 72(sp)
    ld a0, 80(sp)
    ld a1, 88(sp)
    ld a2, 96(sp)
    ld a3, 104(sp)
    ld a4, 112(sp)
    ld a5, 120(sp)
    ld a6, 128(sp)
    ld a7, 136(sp)
    ld s2, 144(sp)
    ld s3, 152(sp)
    ld s4, 160(sp)
    ld s5, 168(sp)
    ld s6, 176(sp)
    ld s7, 184(sp)
    ld s8, 192(sp)
    ld s9, 200(sp)
    ld s10, 208(sp)
    ld s11, 216(sp)
    ld t3, 224(sp)
    ld t4, 232(sp)
    ld t5, 240(sp)
    ld t6, 248(sp)
    ld t0, 40(sp)
    ld sp, 16(sp)
    sret

supervisor_fault_stack:
    # Boot has relinquished this mapped 512 KiB arena before user admission.
    # A supervisor exception is fatal; no interrupted Rust frame is resumed.
    csrw sscratch, zero
    la sp, BOOT_STACK
    li t0, 524288
    add sp, sp, t0
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    tail supervisor_fault_emergency

.globl switch_context
switch_context:
    sd ra, 0(a0)
    sd sp, 8(a0)
    sd s0, 16(a0)
    sd s1, 24(a0)
    sd s2, 32(a0)
    sd s3, 40(a0)
    sd s4, 48(a0)
    sd s5, 56(a0)
    sd s6, 64(a0)
    sd s7, 72(a0)
    sd s8, 80(a0)
    sd s9, 88(a0)
    sd s10, 96(a0)
    sd s11, 104(a0)
    ld ra, 0(a1)
    ld sp, 8(a1)
    ld s0, 16(a1)
    ld s1, 24(a1)
    ld s2, 32(a1)
    ld s3, 40(a1)
    ld s4, 48(a1)
    ld s5, 56(a1)
    ld s6, 64(a1)
    ld s7, 72(a1)
    ld s8, 80(a1)
    ld s9, 88(a1)
    ld s10, 96(a1)
    ld s11, 104(a1)
    ret

.globl enter_user
enter_user:
    mv sp, a0
    j trap_return

.globl enter_scheduler
enter_scheduler:
    mv sp, a0
    tail scheduler_main
