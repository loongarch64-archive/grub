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

#define DEBUG_INFO grub_dprintf ("linux", "DEBUG %d: %s()\n", __LINE__, __FUNCTION__);

#define GRUB_EFI_PE_MAGIC	0x5A4D

#define GRUB_LINUX_LOONGARCH_MAGIC_SIGNATURE 0x4C6F6F6E67417263 /* 'LoongArc' */
#define GRUB_LINUX_LOONGARCH_MAGIC_SIGNATURE2 0x68		/* 'h' */

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
  grub_uint64_t magic;		/* Magic number, little endian, "LoongArc" */
  grub_uint32_t magic1;		/* Magic number, little endian, "h" */
  grub_uint64_t res3;		/* reserved */
  grub_uint32_t hdr_offset;	/* Offset of PE/COFF header */
};

#define linux_arch_kernel_header linux_loongarch64_kernel_header
#include <grub/efi/efi.h>
#include <grub/elfload.h>

void *
allocate_initrd_mem (int initrd_pages);

/* used for the ELF kernel */
//#include <grub/types.h>
//#include <grub/efi/api.h>
//#include <grub/elfload.h>

/* From arch/loongarch/include/asm/mach-loongson64/boot_param.h */
#define GRUB_LOONGSON3_BOOT_MEM_MAP_MAX 128
#define GRUB_ADDRESS_TYPE_SYSRAM	1
#define GRUB_ADDRESS_TYPE_RESERVED	2
#define GRUB_ADDRESS_TYPE_ACPI		3
#define GRUB_ADDRESS_TYPE_NVS		4
#define GRUB_ADDRESS_TYPE_PMEM		5

struct _extention_list_hdr {
    grub_uint64_t		signature;
    grub_uint32_t  		length;
    grub_uint8_t   		revision;
    grub_uint8_t   		checksum;
    struct _extention_list_hdr *next;
} GRUB_PACKED;

struct bootparamsinterface {
    grub_uint64_t		signature;  /* {"B", "P", "I", "0", "1", ... } */
    grub_efi_system_table_t	*systemtable;
    struct _extention_list_hdr	*extlist;
    grub_uint64_t flags;
}GRUB_PACKED;

struct loongsonlist_mem_map {
    struct _extention_list_hdr	header;	/* {"M", "E", "M"} */
    grub_uint8_t		map_count;
    struct memmap {
	grub_uint32_t memtype;
	grub_uint64_t memstart;
	grub_uint64_t memsize;
    } GRUB_PACKED map[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
}GRUB_PACKED;

grub_err_t
grub_arch_elf_linux_boot_image (struct linux_loongarch64_kernel_params
				*kernel_params);

void*
alloc_virtual_mem_addr (grub_addr_t addr, grub_size_t size, grub_err_t *err);

void*
alloc_virtual_mem_align (grub_size_t size, grub_size_t align, grub_err_t *err);

void grub_elf_relocator_unload (void);
//void
//grub_linux_make_argv (struct linux_loongarch64_kernel_params *kernel_params);

int
grub_arch_elf_get_boot_params (struct bootparamsinterface **boot_params);

grub_err_t
grub_arch_elf_boot_params_table (struct bootparamsinterface *boot_params);

grub_err_t
grub_linux_load_elf64 (grub_elf_t elf, const char *filename);

#endif /* ! GRUB_LOONGARCH64_LINUX_HEADER */
