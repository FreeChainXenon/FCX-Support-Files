/* Modified for FreeChainXenon by Aiden Isik, 2025 */

/* Default linker script, for normal executables */
/* Copyright (C) 2014-2024 Free Software Foundation, Inc.
   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */
ENTRY(_start)
OUTPUT_FORMAT(pei-i386)
SEARCH_DIR("/usr/local/fcx/powerpc64-fcx-xenonpe/lib");
SECTIONS
{
  /* Make the virtual address and file offset synced if the alignment is
     lower than the target page size. */
  . = SIZEOF_HEADERS;
  .text  __image_base__ + ( __section_alignment__ < 0x1000 ? . : __section_alignment__ ) :
  {
    *(.text)
  }

  .elf ALIGN(__section_alignment__) :
  {
    *(.elf)
  }

  /DISCARD/ : {*(*)}
}
