#include <inttypes.h>

#include "common.h"
#include "init.h"
#include "util.h"

#define VA_OFFSET 0x100000000ul
#define BIOS_SIZE 0x20000
#define RAM_SIZE  0x200000

uint8_t ptable[0x1000];

static 
void _write_cell(uint64_t *addr, uint64_t deleted, uint64_t valid, uint64_t ppn,
                uint64_t vpn_end_top, uint64_t vpn_end, uint64_t vpn_start) {
  *addr = 0
          | (vpn_end & 0xfffffffull) << 36
          | (vpn_start & 0xfffffffffull) << 0;
  *(addr + 1) = 0
          | (deleted & 0x1ull) << 63
          | (valid & 0x1ull) << 62
          | (ppn & 0xfffffffffffull) << 8
          | (vpn_end_top & 0xffull) << 0;
}

static 
void write_cell(uint64_t *addr, uint64_t va, uint64_t va_end, uint64_t pa) {
  int split = 28;
  return _write_cell(addr, 0, 1, 
                    pa >> 12, 
                    (va_end >> 12) >> split, 
                    (va_end >> 12) & ((1ull << split) - 1), 
                    va >> 12);
}

/* setup_vm operates in PA space */
void setup_vm(void) {
  memset(ptable, 0, sizeof(ptable));

  // Set N = 4, M = 3, T = 1
  uint32_t *ptable_meta = (uint32_t *) ptable;
  ptable_meta[3] = 4;
  ptable_meta[2] = 3;
  ptable_meta[1] = 1;

  uint64_t va_start, va_end, pa;

  /* Setup first cell:  VA=0x1 8002 0000, PA=.data, size=0x4000 */
  pa = (uint64_t)ptable;
  va_start = pa + VA_OFFSET;
  va_end = va_start + 0x4000;
  write_cell((uint64_t *)&ptable[0x10], va_start, va_end, pa);
  cells[0].va_start = va_start;
  cells[0].va_end = va_end;  
  cells[0].pa = pa;

  /* Setup second cell: VA=0x1 8002 4000, PA=.text, size=0x4000 */
  pa       += 0x4000;
  va_start += 0x4000;
  va_end   += 0x4000;
  write_cell((uint64_t *)&ptable[0x20], va_start, va_end, pa);
  cells[1].va_start = va_start;
  cells[1].va_end = va_end;  
  cells[1].pa = pa;

  /* Setup third cell: VA=0x1 8000 8000, PA=.remaining, size=0x1d 8000 */
  pa       += 0x4000;
  va_start += 0x4000;
  va_end = (uint64_t)ptable - BIOS_SIZE + RAM_SIZE + VA_OFFSET;
  write_cell((uint64_t *)&ptable[0x30], va_start, va_end, pa);
  cells[2].va_start = va_start;
  cells[2].va_end = va_end;  
  cells[2].pa = pa;

  uint8_t *perms = ptable + (16 * 64);
  /* Permissions for supervisor: rwx (cf), r-x (cb), rwx (cf) */
  cperms[0][0] = *(perms + (0 * 64) + 1) = 0xcf;
  cperms[0][1] = *(perms + (0 * 64) + 2) = 0xcb;
  cperms[0][2] = *(perms + (0 * 64) + 3) = 0xcf;
  /* Permissions for secdiv SD1: r-- (c3), r-x (cb), rw- (c7) */
  cperms[1][0] = *(perms + (1 * 64) + 1) = 0xc3;
  cperms[1][1] = *(perms + (1 * 64) + 2) = 0xcb;
  cperms[1][2] = *(perms + (1 * 64) + 3) = 0xc7;
  /* Permissions for secdiv SD2: --- (c1), r-x (cb), --- (c1) */
  cperms[2][0] = *(perms + (2 * 64) + 1) = 0xc1;
  cperms[2][1] = *(perms + (2 * 64) + 2) = 0xcb;
  cperms[2][2] = *(perms + (2 * 64) + 3) = 0xc1;

  
}