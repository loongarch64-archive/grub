/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2021  Free Software Foundation, Inc.
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

#ifndef GRUB_LOONGARCH64_LINUX_HEADER
#define GRUB_LOONGARCH64_LINUX_HEADER 1

#include <grub/types.h>

/* LoongArch linux kernel type */
#define GRUB_LOONGARCH_LINUX_BAD 0
#define GRUB_LOONGARCH_LINUX_ELF 1
#define GRUB_LOONGARCH_LINUX_EFI 2

#define GRUB_LOONGSON3_BOOT_MEM_MAP_MAX 128

#define GRUB_LINUX_LOONGARCH_MAGIC_SIGNATURE  0x6E6F73676E6F6F4C /* 'Loongson' */
#define linux_arch_kernel_header linux_loongarch64_kernel_header

/* From linux/Documentation/loongarch/booting.txt
 *
 * 0-1: MZ
 * 0x28: LoongArch\0
 * 0x3c: PE/COFF头偏移
 * 0x20e:内核版本号偏移-512
 * riscv的version字段在0x20偏移处，现在LoongArch没有使用，是0
 */
struct linux_loongarch64_kernel_header
{
  grub_uint32_t code0;		/* Executable code */
  grub_uint32_t code1;		/* Executable code */
  grub_uint64_t text_offset;	/* Image load offset */
  grub_uint64_t res0;		/* reserved */
  grub_uint64_t res1;		/* reserved */
  grub_uint64_t res2;		/* reserved */
  grub_uint64_t magic;		/* Magic number, little endian, "Loongson" */
  grub_uint64_t res3;		/* reserved */
  grub_uint32_t res4;		/* reserved */
  grub_uint32_t hdr_offset;	/* Offset of PE/COFF header */
};

struct linux_loongarch64_kernel_params
{
  grub_addr_t kernel_addr; 		/* kernel entry address */
  grub_size_t kernel_size;		/* kernel size */
  grub_addr_t ramdisk_addr;		/* initrd load address */
  grub_size_t ramdisk_size;		/* initrd size */
  int         linux_argc;
  grub_addr_t linux_argv;
  void*       linux_args;
};

#include <grub/efi/efi.h>
#include <grub/elfload.h>

#define ELF32_LOADMASK (0xf0000000UL)
#define ELF64_LOADMASK (0xf000000000000000ULL)
#define FLAGS_EFI_SUPPORT_BIT 0

/* From arch/loongarch/include/asm/mach-loongson64/boot_param.h */
struct _extention_list_hdr {
    grub_uint64_t		signature;
    grub_uint32_t  		length;
    grub_uint8_t   		revision;
    grub_uint8_t   		checksum;
	union {
      struct  _extention_list_hdr *next;
      grub_uint64_t  next_offset;
    };

} GRUB_PACKED;

struct bootparamsinterface {
    grub_uint64_t		signature;  /* {"B", "P", "I", "0", "1", ... } */
    union {
      grub_efi_system_table_t *systemtable;
      grub_uint64_t  systemtable_offset;
    };
    union {
      struct _extention_list_hdr	*extlist;
      grub_uint64_t  extlist_offset;
    };
    grub_uint64_t flags;
}GRUB_PACKED;

struct loongsonlist_mem_map {
    struct _extention_list_hdr	header;	/* {"M", "E", "M"} */
    grub_uint8_t  map_count;
	grub_uint32_t desc_ver;
    struct memmap {
	grub_uint32_t mem_type;
	grub_uint32_t pad;
	grub_uint64_t mem_start;
	grub_uint64_t virt_start;
	grub_uint64_t mem_size;
	grub_uint64_t attr;
    } GRUB_PACKED map[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
}GRUB_PACKED;

void *
grub_linux_loongarch_efi_allocate_initrd_mem (int initrd_pages);

grub_err_t
grub_linux_loongarch_elf_linux_boot_image (struct linux_loongarch64_kernel_params
					   *kernel_params);

void*
grub_linux_loongarch_alloc_virtual_mem_addr (grub_addr_t addr,
					     grub_size_t size,
					     grub_err_t *err);

void*
grub_linux_loongarch_alloc_virtual_mem_align (grub_size_t size,
					      grub_size_t align,
					      grub_err_t *err);

void
grub_linux_loongarch_elf_relocator_unload (void);

void
grub_linux_loongarch_elf_make_argv (struct linux_loongarch64_kernel_params *kernel_params);

int
grub_linux_loongarch_elf_get_boot_params (struct bootparamsinterface **boot_params);

grub_err_t
grub_linux_loongarch_elf_boot_params (struct bootparamsinterface *boot_params);

grub_err_t
grub_linux_loongarch_elf_load_kernel (grub_elf_t elf, const char *filename);

#endif /* ! GRUB_LOONGARCH64_LINUX_HEADER */
