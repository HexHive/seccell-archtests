
#ifdef __ASSEMBLER__
.global test_entry
#else
#include <inttypes.h>

void test_entry(void);
void set_cell(int cidx, uint64_t va_start, uint64_t va_end, uint64_t pa);
void set_cell_perm(int sdidx, int cidx, uint8_t perm);
#endif
