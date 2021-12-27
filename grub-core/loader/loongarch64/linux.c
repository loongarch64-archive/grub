/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2021 Free Software Foundation, Inc.
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

#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/elf.h>
#include <grub/elfload.h>
#include <grub/loader.h>
#include <grub/dl.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/command.h>
#include <grub/cpu/relocator.h>
#include <grub/memory.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>
#include <grub/linux.h>
#include <grub/cpu/linux.h>
#include <grub/efi/memory.h>

GRUB_MOD_LICENSE ("GPLv3+");

//#define ENABLE_EFI_KERNEL 1

#define ENTER_FUNCTION  grub_dprintf ("linux", "DDDEEEBBBUUUGGG enter %s\n", __FUNCTION__);
#define LEAVE_FUNCTION  grub_dprintf ("linux", "DDDEEEBBBUUUGGG leave %s\n", __FUNCTION__);
#define DEBUG_INFO grub_dprintf ("linux", "DEBUG %d: %s()\n", __LINE__, __FUNCTION__);

typedef  unsigned long size_t;

static grub_dl_t my_mod;

static int loaded;

static grub_uint32_t tmp_index = 0;
static grub_size_t linux_size;

static struct grub_relocator *relocator;
static grub_addr_t entry_addr;
static grub_addr_t phys_addr;
static int linux_argc;
static grub_uint8_t *linux_args_addr;
static grub_off_t rd_addr_arg_off, rd_size_arg_off;
static grub_off_t initrd_addr_arg_off;

grub_uint64_t tempMemsize = 0;
grub_uint32_t free_index = 0;
grub_uint32_t reserve_index = 0;
grub_uint32_t acpi_table_index = 0;
grub_uint32_t acpi_nvs_index = 0;

/* Begin from loongarch64.c */
static struct linux_loongarch64_kernel_params kernel_params;


//struct bootparamsinterface* boot_params;
int
grub_efi_loongarch64_get_boot_params (struct bootparamsinterface **boot_params)
{
#define GRUB_EFI_LOONGSON_SMBIOS_TABLE_GUID	\
    { 0x4660f721, 0x2ec5, 0x416a, \
	{ 0x89, 0x9a, 0x43, 0x18, 0x02, 0x50, 0xa0, 0xc9 } \
    }

  grub_efi_configuration_table_t *tables;
  grub_efi_guid_t smbios_guid = GRUB_EFI_LOONGSON_SMBIOS_TABLE_GUID;
  unsigned int i;
  int found = 0;

  /* Look for Loongson SMBIOS in UEFI config tables. */
  tables = grub_efi_system_table->configuration_table;

  for (i = 0; i < grub_efi_system_table->num_table_entries; i++)
    if (grub_memcmp (&tables[i].vendor_guid, &smbios_guid, sizeof (smbios_guid)) == 0)
      {
	*boot_params = tables[i].vendor_table;
	char *p = (char*) &((*boot_params)->signature);
	if (grub_strncmp (p, "BPI", 3) == 0)
	  {
	    grub_dprintf ("linux", "Found loongson registered SMBIOS @ %p\n", *boot_params);
	    found = 1;
	    break;
	  }
      }
  return found;
}

grub_uint8_t
grub_efi_loongarch64_calculatesum8 (const grub_uint8_t *buffer, grub_efi_uintn_t length)
{
  grub_uint8_t sum;
  grub_efi_uintn_t count;

  for (sum = 0, count = 0; count < length; count++)
  {
    sum = (grub_uint8_t) (sum + *(buffer + count));
  }
  return sum;
}

grub_uint8_t
grub_efi_loongarch64_grub_calculatechecksum8 (const grub_uint8_t *buffer, grub_efi_uintn_t length)
{
  grub_uint8_t checksum;

  checksum = grub_efi_loongarch64_calculatesum8 (buffer, length);

  return (grub_uint8_t) (0x100 - checksum);
}

grub_uint32_t
grub_efi_loongarch64_memmap_sort (struct memmap array[],
				  grub_uint32_t length,
				  struct loongsonlist_mem_map* bpmem,
				  grub_uint32_t index,
				  grub_uint32_t memtype)
{
  grub_uint64_t tempmemsize = 0;
  grub_uint32_t j = 0;
  grub_uint32_t t = 0;

  for(j = 0; j < length;)
  {
    tempmemsize = array[j].memsize;
    for(t = j + 1; t < length; t++)
    {
      if(array[j].memstart + tempmemsize == array[t].memstart)
      {
        tempmemsize += array[t].memsize;
      }
      else
      {
        break;
      }
   }
   bpmem->map[index].memtype = memtype;
   bpmem->map[index].memstart = array[j].memstart;
   bpmem->map[index].memsize = tempmemsize;
   grub_dprintf("loongson", "map[%d]:type %"PRIuGRUB_UINT32_T", start 0x%"
		PRIuGRUB_UINT64_T", end 0x%"PRIuGRUB_UINT64_T"\n",
		index,
		bpmem->map[index].memtype,
		bpmem->map[index].memstart,
		bpmem->map[index].memstart+ bpmem->map[index].memsize
	       );
   j = t;
   index++;
  }
  return index;
}

/* code end from loongarch64.c */

static inline grub_size_t
page_align (grub_size_t size)
{
  return (size + (1 << 12) - 1) & (~((1 << 12) - 1));
}

/* Find the optimal number of pages for the memory map. Is it better to
   move this code to efi/mm.c?  */
static grub_efi_uintn_t
find_mmap_size (void)
{
  static grub_efi_uintn_t mmap_size = 0;

  if (mmap_size != 0)
    return mmap_size;

  mmap_size = (1 << 12);
  while (1)
    {
      int ret;
      grub_efi_memory_descriptor_t *mmap;
      grub_efi_uintn_t desc_size;

      mmap = grub_malloc (mmap_size);
      if (! mmap)
	return 0;

      ret = grub_efi_get_memory_map (&mmap_size, mmap, 0, &desc_size, 0);
      grub_free (mmap);

      if (ret < 0)
	{
	  grub_error (GRUB_ERR_IO, "cannot get memory map");
	  return 0;
	}
      else if (ret > 0)
	break;

      mmap_size += (1 << 12);
    }
  /* Increase the size a bit for safety, because GRUB allocates more on
     later, and EFI itself may allocate more.  */
  mmap_size += (1 << 12);

  return page_align (mmap_size);
}

static void* grub_linux_make_argv (void)
{
  ENTER_FUNCTION
  int size;
  grub_uint64_t *linux_argv;
  char *args, *p, *linux_args;
  int i, argc;
  grub_err_t err;

  argc = kernel_params.linux_argc;
  args = kernel_params.linux_args;


  /* new size */
  p = args;
  size = (argc + 1) * sizeof (grub_uint64_t);  /* orig arguments */
  for (i = 0; i < argc; i++)
    {
      size += ALIGN_UP (grub_strlen (p) + 1, 4);
      p += grub_strlen (p) + 1;
    }

  size += ALIGN_UP (sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), 4) \
	  + ALIGN_UP (sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"), 4) \
	  + ALIGN_UP (sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"), 4);
  size = ALIGN_UP (size, 8);

  /* alloc memory */
  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_align (relocator, &ch,
					    0, (0xffffffff - size) + 1,
					    size, 8,
					    GRUB_RELOCATOR_PREFERENCE_LOW, 0);
    if (err)
      return NULL;
    linux_args_addr = get_virtual_current_address (ch);
  }

  /* 64位指针指向开始地址 */
  linux_argv = linux_args_addr;
  linux_args = (char *) (linux_argv + (argc + 1 + 3)); /* 字符串指针, 指向变量的起始地址  */

  p = args;
  for (i = 0; i < argc; i++)
    {
      grub_memcpy (linux_args, p, grub_strlen (p) + 1);
      *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
      linux_args += ALIGN_UP (grub_strlen (p) + 1, 4);
      p += grub_strlen (p) + 1;
    }

  /* rd_start */
  grub_snprintf (linux_args,
		 sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"),
		 "rd_start=0x%lx",
		 (grub_uint64_t) kernel_params.ramdisk_addr);
  *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
  linux_args += ALIGN_UP (sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), 4);
  linux_argv++;
  kernel_params.linux_argc++;

  /* rd_size */
  grub_snprintf (linux_args,
		 sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"),
		 "rd_size=0x%lx",
		 (grub_uint64_t) kernel_params.ramdisk_size);
  *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
  linux_args += ALIGN_UP (sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"), 4);
  linux_argv++;
  kernel_params.linux_argc++;

  /* initrd */
  grub_snprintf (linux_args,
		 sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"),
		 "initrd=0x%lx,0x%lx",
		 ((grub_uint64_t) kernel_params.ramdisk_addr & 0xffffffff),
		 (grub_uint64_t) kernel_params.ramdisk_size);
  *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
  linux_args += ALIGN_UP (sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"), 4);
  linux_argv++;
  kernel_params.linux_argc++;

  /* Reserve space for initrd arguments.  */
  *linux_argv = 0;

  LEAVE_FUNCTION
  return linux_args_addr;
}

static grub_err_t
grub_linux_boot (void)
{
  ENTER_FUNCTION
  struct grub_relocator64_state state;
  grub_int8_t checksum = 0;
  grub_efi_memory_descriptor_t * lsdesc = NULL;
  grub_uint32_t j = 0;
  grub_uint32_t t = 0;

  grub_memset (&state, 0, sizeof (state));

  DEBUG_INFO;
  //grub_linux_make_argv ();
  DEBUG_INFO;
  /* Boot the kernel.  */
  state.gpr[1] = entry_addr;
  state.gpr[4] = linux_argc;
  state.gpr[5] = (grub_addr_t) linux_args_addr;

  /* Loongson boot params table */
  grub_efi_uintn_t mmap_size;
  grub_efi_uintn_t desc_size;
  grub_efi_memory_descriptor_t *mmap_buf;
  grub_err_t err;
  struct bootparamsinterface *boot_params = NULL;
  struct loongsonlist_mem_map *loongson_mem_map = NULL;

  struct memmap reserve_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
  struct memmap free_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
  struct memmap acpi_table_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
  struct memmap acpi_nvs_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];

  grub_memset (reserve_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);
  grub_memset (free_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);
  grub_memset (acpi_table_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);
  grub_memset (acpi_nvs_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);

  DEBUG_INFO;
  if (grub_efi_loongarch64_get_boot_params (&boot_params) == 0)
    {
  DEBUG_INFO;
      grub_printf("not find param\n");
      return -1;
    } else {
  DEBUG_INFO;
	grub_printf("yetist: find param\n");
    }
  DEBUG_INFO;

  /* Check extlist headers */
  struct _extention_list_hdr* listpointer = NULL;
  listpointer = boot_params->extlist;
  for( ;listpointer != NULL; listpointer = listpointer->next)
    {
      char *pl= (char *)&(listpointer->signature);
      if(grub_strncmp(pl, "MEM", 3) == 0)
	{
	  loongson_mem_map = (struct loongsonlist_mem_map*)listpointer;
	}
    }

  grub_dprintf("linux", "get new parameter interface\n");

  state.gpr[6] = (grub_uint64_t) boot_params;
  mmap_size = find_mmap_size ();
  if (! mmap_size)
    return grub_errno;
  DEBUG_INFO;
  mmap_buf = grub_efi_allocate_any_pages (page_align (mmap_size) >> 12);
  if (! mmap_buf)
    return grub_error (GRUB_ERR_IO, "cannot allocate memory map");

  DEBUG_INFO;
  err = grub_efi_finish_boot_services (&mmap_size, mmap_buf, NULL,
				       &desc_size, NULL);
  if (err)
    return err;

  DEBUG_INFO;
  if (!mmap_buf || !mmap_size || !desc_size)
    return -1;
  tmp_index = loongson_mem_map -> map_count;

  DEBUG_INFO;
  /*
     According to UEFI SPEC,mmap_buf is the accurate Memory Map array \
     now we can fill platform specific memory structure.
     */
  for(lsdesc = mmap_buf; lsdesc < (grub_efi_memory_descriptor_t *)((char *)mmap_buf + mmap_size);
      lsdesc = (grub_efi_memory_descriptor_t *)((char *)lsdesc + desc_size))
    {
      /* Recovery */
      if((lsdesc->type != GRUB_EFI_ACPI_RECLAIM_MEMORY) && \
	 (lsdesc->type != GRUB_EFI_ACPI_MEMORY_NVS) && \
	 (lsdesc->type != GRUB_EFI_RUNTIME_SERVICES_DATA) && \
	 (lsdesc->type != GRUB_EFI_RUNTIME_SERVICES_CODE) && \
	 (lsdesc->type != GRUB_EFI_RESERVED_MEMORY_TYPE) && \
	 (lsdesc->type != GRUB_EFI_PAL_CODE))
	{
	  free_mem[free_index].memtype = GRUB_ADDRESS_TYPE_SYSRAM;
	  free_mem[free_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
	  free_mem[free_index].memsize = lsdesc->num_pages * 4096;
	  free_index++;

	  /*ACPI*/
	}else if((lsdesc->type == GRUB_EFI_ACPI_RECLAIM_MEMORY)){
	    acpi_table_mem[acpi_table_index].memtype = GRUB_ADDRESS_TYPE_ACPI;
	    acpi_table_mem[acpi_table_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
	    acpi_table_mem[acpi_table_index].memsize = lsdesc->num_pages * 4096;
	    acpi_table_index++;
	}else if((lsdesc->type == GRUB_EFI_ACPI_MEMORY_NVS)){
	    acpi_nvs_mem[acpi_nvs_index].memtype = GRUB_ADDRESS_TYPE_NVS;
	    acpi_nvs_mem[acpi_nvs_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
	    acpi_nvs_mem[acpi_nvs_index].memsize = lsdesc->num_pages * 4096;
	    acpi_nvs_index++;

	    /* Reserve */
	}else{
	    reserve_mem[reserve_index].memtype = GRUB_ADDRESS_TYPE_RESERVED;
	    reserve_mem[reserve_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
	    reserve_mem[reserve_index].memsize = lsdesc->num_pages * 4096;
	    reserve_index++;
	}
    }

  DEBUG_INFO;
  /* Recovery sort */
  for(j = 0; j < free_index;)
    {
      tempMemsize = free_mem[j].memsize;
      for(t = j + 1; t < free_index; t++)
	{
	  if((free_mem[j].memstart + tempMemsize == free_mem[t].memstart) && (free_mem[j].memtype == free_mem[t].memtype))
	    {
	      tempMemsize += free_mem[t].memsize;
	    }else{
		break;
	    }
	}

      loongson_mem_map->map[tmp_index].memtype = GRUB_ADDRESS_TYPE_SYSRAM;
      loongson_mem_map->map[tmp_index].memstart = free_mem[j].memstart;
      loongson_mem_map->map[tmp_index].memsize = tempMemsize;
      grub_dprintf("linux", "map[%d]:type %"PRIuGRUB_UINT32_T", "
		   "start 0x%"PRIxGRUB_UINT64_T", "
		   "end 0x%"PRIuGRUB_UINT64_T"\n",
		   tmp_index,
		   loongson_mem_map->map[tmp_index].memtype,
		   loongson_mem_map->map[tmp_index].memstart,
		   loongson_mem_map->map[tmp_index].memstart+ loongson_mem_map->map[tmp_index].memsize
		  );
      j = t;
      tmp_index++;
    }

  DEBUG_INFO;
  /*Reserve Sort*/
  grub_uint64_t loongarch_addr;
  asm volatile ("csrrd %0, 0x181" : "=r" (loongarch_addr));
  if((loongarch_addr & 0xff00000000000000) == 0x9000000000000000){
      tmp_index = grub_efi_loongarch64_memmap_sort (reserve_mem, reserve_index, loongson_mem_map, tmp_index, GRUB_ADDRESS_TYPE_RESERVED);
  }else{
      tmp_index = grub_efi_loongarch64_memmap_sort (reserve_mem, reserve_index, loongson_mem_map, tmp_index, GRUB_ADDRESS_TYPE_RESERVED + 1);
  }

  loongson_mem_map->map_count = tmp_index;
  loongson_mem_map->header.checksum = 0;

  checksum = grub_efi_loongarch64_grub_calculatechecksum8 ((grub_uint8_t *) loongson_mem_map,
							   loongson_mem_map->header.length);
  loongson_mem_map->header.checksum = checksum;

  DEBUG_INFO;
  state.jumpreg = 1;
  grub_relocator64_boot (relocator, state);

  DEBUG_INFO;
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_linux_unload (void)
{
  grub_relocator_unload (relocator);
  grub_dl_unref (my_mod);

  loaded = 0;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_linux_load_elf64 (grub_elf_t elf, const char *filename)
{
  Elf64_Addr base;
  grub_err_t err;
  grub_uint8_t *playground;

  /* Linux's entry point incorrectly contains a virtual address.  */
  entry_addr = elf->ehdr.ehdr64.e_entry;
  linux_size = grub_elf64_size (elf, &base, 0);

  kernel_params.kernel_addr = entry_addr; //playground - base;
  kernel_params.kernel_size = linux_size;

  if (linux_size == 0)
    return grub_errno;

  phys_addr = base;
  linux_size = ALIGN_UP (base + linux_size - base, 8);

  relocator = grub_relocator_new ();
  if (!relocator)
    return grub_errno;

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					   grub_vtop ((void *) phys_addr),
					   linux_size);
    if (err)
      return err;
    playground = get_virtual_current_address (ch);
  }

  /* Now load the segments into the area we claimed.  */
  return grub_elf64_load (elf, filename, playground - base, GRUB_ELF_LOAD_FLAGS_NONE, 0, 0);
}

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_elf_t elf = 0;
  int size;
  int i;
  grub_uint64_t *linux_argv;
  char *linux_args;
  grub_err_t err;

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  elf = grub_elf_open (argv[0],GRUB_FILE_TYPE_LINUX_KERNEL);
  if (! elf)
    return grub_errno;

  if (elf->ehdr.ehdr32.e_type != ET_EXEC)
    {
      grub_elf_close (elf);
      return grub_error (GRUB_ERR_UNKNOWN_OS,
			 N_("this ELF file is not of the right type"));
    }

  /* Release the previously used memory.  */
  grub_loader_unset ();
  loaded = 0;

  /* For arguments.  */
  linux_argc = argc;
  /* Main arguments.  */
  size = (linux_argc) * sizeof (grub_uint64_t);
  /* Initrd address/size and initrd  */
  size += 3 * sizeof (grub_uint64_t);
  /* NULL terminator.  */
  size += sizeof (grub_uint64_t);
  /* First argument is always "a0".  */
  size += ALIGN_UP (sizeof ("a0"), 4);
  /* Normal arguments.  */
  for (i = 1; i < argc; i++)
    size += ALIGN_UP (grub_strlen (argv[i]) + 1, 4);

  /* rd arguments.  */
  size += ALIGN_UP (sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), 4);
  size += ALIGN_UP (sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"), 4);
  size += ALIGN_UP (sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"), 4);

  size = ALIGN_UP (size, 8);

  if (grub_elf_is_elf64 (elf))
    err = grub_linux_load_elf64 (elf, argv[0]);
  else
    err = grub_error (GRUB_ERR_BAD_OS, N_("invalid arch-dependent ELF magic"));

  grub_elf_close (elf);

#ifdef ENABLE_EFI_KERNEL
  cmdline_size = grub_loader_cmdline_size (argc, argv) + sizeof (LINUX_IMAGE);
  linux_args = grub_malloc (cmdline_size);
  if (!linux_args)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }
  grub_memcpy (linux_args, LINUX_IMAGE, sizeof (LINUX_IMAGE));
  err = grub_create_loader_cmdline (argc, argv,
				    linux_args + sizeof (LINUX_IMAGE) - 1,
				    cmdline_size,
				    GRUB_VERIFY_KERNEL_CMDLINE);
#endif
  if (err)
    return err;

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_align (relocator, &ch,
					    0, (0xffffffff - size) + 1,
					    size, 8,
					    GRUB_RELOCATOR_PREFERENCE_LOW, 0);
    if (err)
      return err;
    linux_args_addr = get_virtual_current_address (ch);
  }

  linux_argv = (void*) linux_args_addr;
  linux_args = (char *) (linux_argv + (linux_argc + 1 + 3));

  grub_memcpy (linux_args, "a0", sizeof ("a0"));
  *linux_argv = (grub_uint64_t) linux_args;
  linux_argv++;
  linux_args += ALIGN_UP (sizeof ("a0"), 4);

  for (i = 1; i < argc; i++)
    {
      grub_memcpy (linux_args, argv[i], grub_strlen (argv[i]) + 1);
      *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
      linux_argv++;
      linux_args += ALIGN_UP (grub_strlen (argv[i]) + 1, 4);
    }

  /* Reserve space for rd arguments.  */
  rd_addr_arg_off = (grub_uint8_t *) linux_args - linux_args_addr;
  linux_args += ALIGN_UP (sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), 4);
  *linux_argv = 0;
  linux_argv++;

  rd_size_arg_off = (grub_uint8_t *) linux_args - linux_args_addr;
  linux_args += ALIGN_UP (sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"), 4);
  *linux_argv = 0;
  linux_argv++;

  /* Reserve space for initrd arguments.  */
  initrd_addr_arg_off = (grub_uint8_t *) linux_args - linux_args_addr;
  linux_args += ALIGN_UP (sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"), 4);
  *linux_argv = 0;
  linux_argv++;

  *linux_argv = 0;

  grub_loader_set (grub_linux_boot, grub_linux_unload, 0);
  loaded = 1;
  grub_dl_ref (my_mod);

#if 0
  /* save args from linux cmdline */
  char *p;
  grub_uint32_t cmdline_size;
  cmdline_size = grub_loader_cmdline_size (argc, argv) + sizeof (LINUX_IMAGE);
  kernel_params.linux_argc = argc;
  kernel_params.linux_args = grub_malloc (cmdline_size);

  if (!kernel_params.linux_args)
    {
      return grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      //goto fail;
    }
  p = kernel_params.linux_args;
  grub_memcpy (p, LINUX_IMAGE, sizeof (LINUX_IMAGE));
  p += sizeof (LINUX_IMAGE) - 1;
  for (i=0; i < argc; i++)
    {
      grub_memcpy (p, argv[i], sizeof(argv[i]));
      p += sizeof(argv[i]);
    }
#endif
  return GRUB_ERR_NONE;
}

#ifdef ENABLE_EFI_KERNEL
#define INITRD_MAX_ADDRESS_OFFSET (32ULL * 1024 * 1024 * 1024)
static void *
allocate_initrd_mem (int initrd_pages)
{
  grub_addr_t max_addr;

  if (grub_efi_get_ram_base (&max_addr) != GRUB_ERR_NONE)
    return NULL;

  max_addr += INITRD_MAX_ADDRESS_OFFSET - 1;

  return grub_efi_allocate_pages_real (max_addr, initrd_pages,
				       GRUB_EFI_ALLOCATE_MAX_ADDRESS,
				       GRUB_EFI_LOADER_DATA);
}
#endif

static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)),
		 int argc, char *argv[])
{
  struct grub_linux_initrd_context initrd_ctx = { 0, 0, 0 };
  grub_size_t initrd_size;
  void *initrd_mem = NULL;

  if (argc == 0)
    {
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  if (!loaded)
    {
      return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("you need to load the kernel first"));
      goto fail;
    }

  if (grub_initrd_init (argc, argv, &initrd_ctx))
    goto fail;

  initrd_size = grub_get_initrd_size (&initrd_ctx);
  grub_dprintf ("linux", "Loading initrd\n");

#ifdef ENABLE_EFI_KERNEL
  //grub_size_t initrd_pages;
  initrd_pages = (GRUB_EFI_BYTES_TO_PAGES (initrd_size));
  initrd_mem = allocate_initrd_mem (initrd_pages);

  if (!initrd_mem)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }
#else
  {
  grub_relocator_chunk_t ch;
  grub_err_t err;
  err = grub_relocator_alloc_chunk_align (relocator, &ch,
					  0, (0xffffffff - initrd_size) + 1,
					  initrd_size, 0x10000,
					  GRUB_RELOCATOR_PREFERENCE_LOW, 0);

  if (err)
    goto fail;
  initrd_mem = get_virtual_current_address (ch);
  }
#endif

  if (grub_initrd_load (&initrd_ctx, argv, initrd_mem))
    goto fail;

  kernel_params.ramdisk_addr = (grub_addr_t) initrd_mem;
  kernel_params.ramdisk_size = initrd_size;
  grub_dprintf ("linux", "ramdisk [addr=%p, size=0x%lx]\n",
		(void *) initrd_mem, initrd_size);

  grub_addr_t initrd_start;
  grub_addr_t initrd_end;

  initrd_start = (grub_addr_t) initrd_mem;
  initrd_end = initrd_start + initrd_size;
  grub_dprintf ("linux", "[addr=%p, size=0x%"PRIuGRUB_SIZE"]\n",
		(void *) initrd_start, initrd_size);

  grub_snprintf ((char *) linux_args_addr + rd_addr_arg_off,
		 sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), "rd_start=0x%lx",
		 (grub_uint64_t) initrd_start);
  ((grub_uint64_t *) linux_args_addr)[linux_argc]
    = (grub_uint64_t) ((grub_addr_t) linux_args_addr + rd_addr_arg_off);
  linux_argc++;

  grub_snprintf ((char *) linux_args_addr + rd_size_arg_off,
		 sizeof ("rd_size=0xXXXXXXXXXXXXXXXXX"), "rd_size=0x%lx",
		 (grub_uint64_t) initrd_size);
  ((grub_uint64_t *) linux_args_addr)[linux_argc]
    = (grub_uint64_t) ((grub_addr_t) linux_args_addr + rd_size_arg_off);
  linux_argc++;


  grub_snprintf ((char *) linux_args_addr + initrd_addr_arg_off,
		 sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"), "initrd=0x%lx,0x%lx",
		 ((grub_uint64_t) initrd_start & 0xffffffff), (grub_uint64_t) initrd_size);
  ((grub_uint64_t *) linux_args_addr)[linux_argc]
    = (grub_uint64_t) ((grub_addr_t) linux_args_addr + initrd_addr_arg_off);
  linux_argc++;

fail:
  grub_initrd_close (&initrd_ctx);
#ifdef ENABLE_EFI_KERNEL
  if (initrd_mem && !initrd_start)
    grub_efi_free_pages ((grub_addr_t) initrd_mem, initrd_pages);
#endif
  return grub_errno;
}

static grub_command_t cmd_linux, cmd_initrd;

GRUB_MOD_INIT(linux)
{
  cmd_linux = grub_register_command ("linux", grub_cmd_linux,
				     N_("FILE [ARGS...]"), N_("Load Linux."));
  cmd_initrd = grub_register_command ("initrd", grub_cmd_initrd,
				      N_("FILE"), N_("Load initrd."));
  my_mod = mod;
}

GRUB_MOD_FINI(linux)
{
  grub_unregister_command (cmd_linux);
  grub_unregister_command (cmd_initrd);
}
