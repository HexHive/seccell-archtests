/*
 * Layout:
 * 0x8000 0000 - 0x8002 0000   : Reserved for OpenSBI
 * 0x8002 0000 - 0x8002 3fff   : 16kB data/bss
 * 0x8002 4000                 : Entry
 * 0x8002 4000 - 0x8002 8000   : 16kB code
 * 0x8002 8000 - 0x8020 0000   : Unused/Free use
 *
 */

ENTRY(_entry)
SECTIONS
{
  . = 0x80020000;
  .bss : {
    init.o(.bss)
    *.o(.bss)
  }
  . = 0x80024000;
  .text : {
    *.o(.text)
  }
}
