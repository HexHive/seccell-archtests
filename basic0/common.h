#include <inttypes.h>

struct cell {
  uint64_t va_start, va_end, pa;
};


extern struct cell cells[3];
extern uint8_t cperms[3][3];
