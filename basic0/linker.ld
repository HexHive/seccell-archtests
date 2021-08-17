/*
 * Layout:
 * 0x8000 0000 - 0x8004 0000   : Reserved for OpenSBI
 * 0x8004 0000 - 0x8004 3fff   : 16kB data/bss
 * 0x8004 4000                 : Entry
 * 0x8004 4000 - 0x8004 8000   : 16kB code
 * 0x8004 8000 - 0x8020 0000   : Unused/Free use
 *
 */

ENTRY(_entry)
SECTIONS
{
  . = 0x80040000;
  .bss : {
    init.o(.bss)
    *.o(.bss)
  }
  . = 0x80044000;
  .text : {
    *.o(.text)
  }
}
