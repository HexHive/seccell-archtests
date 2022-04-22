#include "init.h"
#include "test.h"

.section .init, "ax"

.global _entry
_entry:
  # Setup stack
  la t0, ptable
  li t1, BIOS_SIZE     
  sub t0, t0, t1
  li t1, RAM_SIZE    
  add t0, t0, t1
  /* Reserve a token 16B at the top of the RAM,
   * and denote the rest as stack */
  add t0, t0, -16
  mv sp, t0

  # Setup PTable and drop into virtual memory
  /* Move into virtual memory using cool Linux trick:
   *
   * Setup STVEC to VA of instruction at next marker '1'.
   * Then write SATP, and flush. 
   * The SATP update will cause a fault, as the physical address PC
   * is invalid, moving to stvec. 
   * Now executing in virtual mem, at instruction '1'.
   */
  call setup_vm
  la t0, first_va_inst
  li t1, VA_OFFSET
  add t0, t0, t1
  csrw stvec, t0
# li t0, 0
# csrw usid, t0
  li t0, 0xf         # SATP_MODE 0xf 
  slli t0, t0, 60
  la t1, ptable
  srli t1, t1, 12
  or t0, t0, t1
  csrw satp, t0
  sfence.vma  
first_va_inst:
  nop
  la t0, exception_handler
  csrw stvec, t0
  call setup_trap_handler
  mv tp, zero
  # Fix stack pointer
  li t0, VA_OFFSET
  add sp, sp, t0

  # Drop into test as user with SD1
  la t0, test
  csrw sepc, t0
  li t0, 1
  csrw urid, t0
  li t0, 0
  csrw uxid, t0

  # drop to u-mode
  li t0, 1 << 8 # sstatus.spp
  csrc sstatus, t0

drop_to_test:
  sret

exception_handler:
  # Initial: tp = 0, sscratch = &ctx
  # Final: tp = &ctx, sscratch = 0
  csrrw tp, sscratch, tp
  # Bad initial value: tp = whatever, sscratch = 0
  # This happens if there is an exception while handling an exception
  beqz tp, bad_exception 
  sd x1,  8(tp)
	sd x3,  24(tp)
	sd x5,  40(tp)
	sd x6,  48(tp)
	sd x7,  56(tp)
	sd x8,  64(tp)
	sd x9,  72(tp)
	sd x10, 80(tp)
	sd x11, 88(tp)
	sd x12, 96(tp)
	sd x13, 104(tp)
	sd x14, 112(tp)
	sd x15, 120(tp)
	sd x16, 128(tp)
	sd x17, 136(tp)
	sd x18, 144(tp)
	sd x19, 152(tp)
	sd x20, 160(tp)
	sd x21, 168(tp)
	sd x22, 176(tp)
	sd x23, 184(tp)
	sd x24, 192(tp)
	sd x25, 200(tp)
	sd x26, 208(tp)
	sd x27, 216(tp)
	sd x28, 224(tp)
	sd x29, 232(tp)
	sd x30, 240(tp)
	sd x31, 248(tp)
  csrr t0, sstatus
  sd t0, 256(tp)
  csrr t0, sepc
  sd t0, 264(tp)
  csrr t0, scause
  sd t0, 272(tp)
  csrr t0, stval
  sd t0, 280(tp)
  csrr t0, urid
  sd t0, 288(tp)
  csrr t0, uxid
  sd t0, 296(tp)

  call c_trap_handler
  
  ld t0, 256(tp)
  csrw sstatus, t0
  ld t0, 264(tp)
  csrw sepc, t0
  ld t0, 288(tp)
  csrw urid, t0
  ld t0, 296(tp)
  csrw uxid, t0
  ld x1, 8(tp)
  ld x3, 24(tp)
  ld x5, 40(tp)
  ld x6, 48(tp)
  ld x7, 56(tp)
  ld x8, 64(tp)
  ld x9, 72(tp)
  ld x10, 80(tp)
  ld x11, 88(tp)
  ld x12, 96(tp)
  ld x13, 104(tp)
  ld x14, 112(tp)
  ld x15, 120(tp)
  ld x16, 128(tp)
  ld x17, 136(tp)
  ld x18, 144(tp)
  ld x19, 152(tp)
  ld x20, 160(tp)
  ld x21, 168(tp)
  ld x22, 176(tp)
  ld x23, 184(tp)
  ld x24, 192(tp)
  ld x25, 200(tp)
  ld x26, 208(tp)
  ld x27, 216(tp)
  ld x28, 224(tp)
  ld x29, 232(tp)
  ld x30, 240(tp)
  ld x31, 248(tp)
  csrrw tp, sscratch, tp
  sret

bad_exception:
  j bad_exception
