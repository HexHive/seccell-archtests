/*
 * Layout:
 * 0x8000 0000 - 0x8000 3fff   : 16kB data
 * 0x8000 4000                 : Entry
 * 0x8000 4000 - 0x8000 8000   : 16kB code
 * 0x8000 8000 - 0x8020 0000   : Unused/Free use
 *
 */

ENTRY(_entry)
SECTIONS
{
  . = 0x80000000;
  .data : {
    *.o(.data)
  }
  . = 0x80004000;
  .text : {
    *.o(.text)
  }
}
