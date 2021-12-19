/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2021  Loongson Technology Corporation Limited
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_EFI_LOONGSON_HEADER
#define GRUB_EFI_LOONGSON_HEADER 1

#include <grub/types.h>
#include <grub/efi/api.h>

#define GRUB_EFI_LOONGSON_SMBIOS_TABLE_GUID	\
  { 0x4660f721, 0x2ec5, 0x416a, \
    { 0x89, 0x9a, 0x43, 0x18, 0x02, 0x50, 0xa0, 0xc9 } \
  }

#define GRUB_EFI_LOONGSON_MMAP_MAX 128
typedef enum
  {
    GRUB_EFI_LOONGSON_SYSTEM_RAM = 1,
    GRUB_EFI_LOONGSON_MEMORY_RESERVED,
    GRUB_EFI_LOONGSON_ACPI_TABLE,
    GRUB_EFI_LOONGSON_ACPI_NVS,
    GRUB_EFI_LOONGSON_MAX_MEMORY_TYPE
  }
grub_efi_loongarch64_memory_type;

int EXPORT_FUNC(grub_efi_is_loongarch64) (void);

grub_uint8_t
EXPORT_FUNC(grub_efi_loongarch64_calculatesum8) (const grub_uint8_t *Buffer, grub_efi_uintn_t Length);

grub_uint8_t
EXPORT_FUNC(grub_efi_loongarch64_grub_calculatechecksum8) (const grub_uint8_t *Buffer, grub_efi_uintn_t Length);


void *
EXPORT_FUNC(grub_efi_loongarch64_get_boot_params) (void);

typedef struct _extention_list_hdr{
  grub_uint64_t  signature;
  grub_uint32_t  length;
  grub_uint8_t   revision;
  grub_uint8_t   checksum;
  struct  _extention_list_hdr *next;
}GRUB_PACKED
ext_list;

typedef struct bootparamsinterface {
  grub_uint64_t           signature;    //{'B', 'P', 'I', '_', '0', '_', '1'}
  grub_efi_system_table_t *systemtable;
  ext_list         *extlist;
}GRUB_PACKED
bootparamsinterface;

typedef struct {
  ext_list  header;         //  {'M', 'E', 'M'}
  grub_uint8_t mapcount;
  struct GRUB_PACKED memmap {
    grub_uint32_t memtype;
    grub_uint64_t memstart;
    grub_uint64_t memsize;
  } map[GRUB_EFI_LOONGSON_MMAP_MAX];
}GRUB_PACKED
mem_map;

typedef struct {
  ext_list header;          // {VBIOS}
  grub_uint64_t  vbiosaddr;
}GRUB_PACKED
vbios;

grub_uint32_t
EXPORT_FUNC (grub_efi_loongarch64_memmap_sort) (struct memmap array[], grub_uint32_t length, mem_map * bpmem, grub_uint32_t index, grub_uint32_t memtype);
#endif /* ! GRUB_EFI_LOONGSON_HEADER */
