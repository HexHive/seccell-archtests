
#ifdef __ASSEMBLER__
.global test_entry
.global setup_trap_handle
.global c_trap_handler
#else
#include <inttypes.h>

void set_ptable(uint8_t *, uint32_t M, uint32_t N, uint32_t R, uint32_t T);
void set_cell(int cidx, uint64_t va_start, uint64_t va_end, uint64_t pa);
void set_cell_perm(int sdidx, int cidx, uint8_t perm);
#endif
