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

#include <grub/cpu/linux.h>
#include <grub/linux.h>
#include <grub/efi/efi.h>
#include <grub/elfload.h>
#include <grub/cpu/relocator.h>
#include <grub/efi/memory.h>

#define GRUB_ADDRESS_TYPE_SYSRAM	1
#define GRUB_ADDRESS_TYPE_RESERVED	2
#define GRUB_ADDRESS_TYPE_ACPI		3
#define GRUB_ADDRESS_TYPE_NVS		4
#define GRUB_ADDRESS_TYPE_PMEM		5
#define GRUB_EFI_LOONGSON_BPI_TABLE_GUID	\
    { 0x4660f721, 0x2ec5, 0x416a, \
	{ 0x89, 0x9a, 0x43, 0x18, 0x02, 0x50, 0xa0, 0xc9 } \
    }

static struct grub_relocator *relocator;

void grub_linux_loongarch_elf_relocator_unload (void)
{
  grub_relocator_unload (relocator);
}

void
grub_linux_loongarch_elf_make_argv (struct linux_loongarch64_kernel_params *kernel_params)
{
  static void* linux_args_addr;
  int size;
  grub_uint64_t *linux_argv;
  char *args, *p, *linux_args;
  int i, argc;
  grub_err_t err;

  argc = kernel_params->linux_argc;
  args = kernel_params->linux_args;

  /* new size */
  p = args;
  size = (argc + 3 + 1) * sizeof (grub_uint64_t);  /* orig arguments */
  for (i = 0; i < argc; i++)
    {
      size += ALIGN_UP (grub_strlen (p) + 1, 4);
      p += grub_strlen (p) + 1;
    }

  size += ALIGN_UP (sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), 4) \
	  + ALIGN_UP (sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"), 4) \
	  + ALIGN_UP (sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"),
		      4);
  size = ALIGN_UP (size, 8);

  /* alloc memory */
  linux_args_addr = grub_linux_loongarch_alloc_virtual_mem_align (size, 8, &err);

  linux_argv = linux_args_addr;
  linux_args = (char *)(linux_argv + (argc + 1 + 3));
  p = args;
  for (i = 0; i < argc; i++)
    {
      grub_memcpy (linux_args, p, grub_strlen (p) + 1);
      *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
      linux_argv++;
      linux_args += ALIGN_UP (grub_strlen (p) + 1, 4);
      p += grub_strlen (p) + 1;
    }

  /* rd_start */
  grub_snprintf (linux_args,
		 sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"),
		 "rd_start=0x%lx",
		 (grub_uint64_t) kernel_params->ramdisk_addr);
  *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
  linux_argv++;
  linux_args += ALIGN_UP (sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), 4);
  kernel_params->linux_argc++;

  /* rd_size */
  grub_snprintf (linux_args,
		 sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"),
		 "rd_size=0x%lx",
		 (grub_uint64_t) kernel_params->ramdisk_size);
  *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
  linux_argv++;
  linux_args += ALIGN_UP (sizeof ("rd_size=0xXXXXXXXXXXXXXXXX"), 4);
  kernel_params->linux_argc++;

  /* initrd */
  grub_snprintf (linux_args,
		 sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"),
		 "initrd=0x%lx,0x%lx",
		 ((grub_uint64_t) kernel_params->ramdisk_addr & 0xffffffff),
		 (grub_uint64_t) kernel_params->ramdisk_size);
  *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
  linux_argv++;
  linux_args += ALIGN_UP (sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"), 4);
  kernel_params->linux_argc++;

  /* Reserve space for initrd arguments.  */
  *linux_argv = 0;

  grub_free (kernel_params->linux_args);
  kernel_params->linux_argv = (grub_addr_t) linux_args_addr;
}

grub_err_t
grub_linux_loongarch_elf_linux_boot_image (struct linux_loongarch64_kernel_params
					   *kernel_params)
{
  struct bootparamsinterface *boot_params = NULL;
  struct grub_relocator64_state state;
  grub_err_t err;

  /* linux kernel type is ELF */
  grub_memset (&state, 0, sizeof (state));

  if (grub_linux_loongarch_elf_get_boot_params (&boot_params) == 0)
    {
      grub_printf("not find param\n");
      return -1;
    } else {
      grub_printf("yetist: find param\n");
    }

  /* Boot the ELF kernel */
  grub_linux_loongarch_elf_make_argv (kernel_params);
  state.gpr[1] = kernel_params->kernel_addr;  /* ra */
  state.gpr[4] = kernel_params->linux_argc;   /* a0 = argc */
  state.gpr[5] = kernel_params->linux_argv; /* a1 = args */
  state.gpr[6] = (grub_uint64_t) boot_params; /* a2 = envp */
  state.jumpreg = 1;

  err = grub_linux_loongarch_elf_boot_params (boot_params);
  if (err)
    return err;
  grub_relocator64_boot (relocator, state);

  return GRUB_ERR_NONE;
}

void*
grub_linux_loongarch_alloc_virtual_mem_addr (grub_addr_t addr,
					     grub_size_t size,
					     grub_err_t *err)
{
  relocator = grub_relocator_new ();
  if (!relocator)
    return NULL;

  grub_relocator_chunk_t ch;
  *err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					 grub_vtop ((void *) addr),
					 size);
  if (*err)
    return NULL;
  return get_virtual_current_address (ch);
}


void*
grub_linux_loongarch_alloc_virtual_mem_align (grub_size_t size,
					      grub_size_t align,
					      grub_err_t *err)
{
  grub_relocator_chunk_t ch;

  *err = grub_relocator_alloc_chunk_align (relocator, &ch,
					  0, (0xffffffff - size) + 1,
					  size, align,
					  GRUB_RELOCATOR_PREFERENCE_HIGH, 0);
  return get_virtual_current_address (ch);
}

int
grub_linux_loongarch_elf_get_boot_params (struct bootparamsinterface **boot_params)
{
  grub_efi_configuration_table_t *tables;
  grub_efi_guid_t bpi_guid = GRUB_EFI_LOONGSON_BPI_TABLE_GUID;
  unsigned int i;
  int found = 0;

  /* Look for Loongson BPI in UEFI config tables. */
  tables = grub_efi_system_table->configuration_table;

  for (i = 0; i < grub_efi_system_table->num_table_entries; i++)
    if (grub_memcmp (&tables[i].vendor_guid, &bpi_guid, sizeof (bpi_guid)) == 0)
      {
	*boot_params = tables[i].vendor_table;
	char *p = (char*) &((*boot_params)->signature);
	if (grub_strncmp (p, "BPI", 3) == 0)
	  {
	    found = 1;
	    break;
	  }
      }
  return found;
}

static grub_uint8_t
grub_kernel_update_checksum (const grub_uint8_t *buffer, grub_efi_uintn_t length)
{
  grub_uint8_t sum;
  grub_efi_uintn_t count;

  for (sum = 0, count = 0; count < length; count++)
  {
    sum = (grub_uint8_t) (sum + *(buffer + count));
  }

  return (grub_uint8_t) (0x100 - sum);
}

static grub_uint32_t
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
    tempmemsize = array[j].mem_size;
    for(t = j + 1; t < length; t++)
    {
      if(array[j].mem_start + tempmemsize == array[t].mem_start)
      {
        tempmemsize += array[t].mem_size;
      }
      else
      {
        break;
      }
    }
    bpmem->map[index].mem_type = memtype;
    bpmem->map[index].mem_start = array[j].mem_start;
    bpmem->map[index].mem_size = tempmemsize;
    grub_printf("map[%d]:type %"PRIuGRUB_UINT32_T", start 0x%"
		PRIxGRUB_UINT64_T", end 0x%"PRIxGRUB_UINT64_T"\n",
		index,
		bpmem->map[index].mem_type,
		bpmem->map[index].mem_start,
		bpmem->map[index].mem_start+ bpmem->map[index].mem_size
	       );
    j = t;
    index++;
  }
  return index;
}

/* Find the optimal number of pages for the memory map. Is it better to
   move this code to efi/mm.c?  */
static grub_efi_uintn_t
find_mmap_size (void)
{
  static grub_efi_uintn_t mmap_size = 0;

  if (mmap_size != 0)
    return mmap_size;

  mmap_size = GRUB_EFI_PAGE_SIZE;
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

      mmap_size += GRUB_EFI_PAGE_SIZE;
    }
  /* Increase the size a bit for safety, because GRUB allocates more on
     later, and EFI itself may allocate more.  */
  mmap_size += GRUB_EFI_PAGE_SIZE;

  return ALIGN_UP(mmap_size, GRUB_EFI_PAGE_SIZE);
}

grub_err_t
grub_linux_loongarch_elf_boot_params (struct bootparamsinterface *boot_params)
{
  grub_int8_t checksum = 0;
  grub_err_t err;

  struct loongsonlist_mem_map *loongson_mem_map = NULL;
  void *systab_temp = NULL;
  grub_uint32_t tmp_index = 0;
  grub_efi_memory_descriptor_t * lsdesc = NULL;

  grub_uint32_t free_index = 0;
  grub_uint32_t reserve_index = 0;
  grub_uint32_t acpi_table_index = 0;
  grub_uint32_t acpi_nvs_index = 0;

  grub_efi_uintn_t mmap_size;
  grub_efi_uintn_t desc_size;
  grub_efi_memory_descriptor_t *mmap_buf;

  struct memmap reserve_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
  struct memmap free_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
  struct memmap acpi_table_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];
  struct memmap acpi_nvs_mem[GRUB_LOONGSON3_BOOT_MEM_MAP_MAX];

  grub_memset (reserve_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);
  grub_memset (free_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);
  grub_memset (acpi_table_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);
  grub_memset (acpi_nvs_mem, 0, sizeof(struct memmap) * GRUB_LOONGSON3_BOOT_MEM_MAP_MAX);

  boot_params->systemtable_offset = sizeof(*boot_params);
  boot_params->extlist_offset = sizeof(*boot_params) + sizeof(*grub_efi_system_table);
  boot_params->flags = 1 << FLAGS_EFI_SUPPORT_BIT;
  systab_temp = (char *)boot_params + boot_params->systemtable_offset;
  grub_efi_system_table->runtime_services = NULL;
  memcpy(systab_temp, grub_efi_system_table, sizeof(*grub_efi_system_table));

  loongson_mem_map = (struct loongsonlist_mem_map*)((char *)boot_params + boot_params->extlist_offset);
  memset(&loongson_mem_map->header, 0, sizeof(struct _extention_list_hdr));
  memcpy(&loongson_mem_map->header.signature, "MEM", sizeof(grub_uint64_t));
  loongson_mem_map->header.revision = 0;
  loongson_mem_map->header.length = sizeof(*loongson_mem_map);

  mmap_size = find_mmap_size ();
  if (! mmap_size)
    return grub_errno;
  mmap_buf = grub_efi_allocate_any_pages (ALIGN_UP (mmap_size, GRUB_EFI_PAGE_SIZE) >> 12);
  if (! mmap_buf)
    return grub_error (GRUB_ERR_IO, "cannot allocate memory map");

  err = grub_efi_finish_boot_services (&mmap_size, mmap_buf, NULL,
				       &desc_size, NULL);
  if (err)
    return err;

  if (!mmap_buf || !mmap_size || !desc_size)
    return -1;

  /*
     According to UEFI SPEC,mmap_buf is the accurate Memory Map array \
     now we can fill platform specific memory structure.
     */
  for (lsdesc = mmap_buf; lsdesc < (grub_efi_memory_descriptor_t *)((char *)mmap_buf + mmap_size);
      lsdesc = (grub_efi_memory_descriptor_t *)((char *)lsdesc + desc_size))
    {
      /* System RAM */
      if((lsdesc->type != GRUB_EFI_ACPI_RECLAIM_MEMORY) && \
	 (lsdesc->type != GRUB_EFI_ACPI_MEMORY_NVS) && \
	 (lsdesc->type != GRUB_EFI_RUNTIME_SERVICES_DATA) && \
	 (lsdesc->type != GRUB_EFI_RUNTIME_SERVICES_CODE) && \
	 (lsdesc->type != GRUB_EFI_RESERVED_MEMORY_TYPE) && \
	 (lsdesc->type != GRUB_EFI_PAL_CODE))
	{
	  free_mem[free_index].mem_type = GRUB_ADDRESS_TYPE_SYSRAM;
	  free_mem[free_index].mem_start = (lsdesc->physical_start) & 0xffffffffffff;
	  free_mem[free_index].mem_size = lsdesc->num_pages * GRUB_EFI_PAGE_SIZE;
	  free_index++;

	  /*ACPI*/
	}else if((lsdesc->type == GRUB_EFI_ACPI_RECLAIM_MEMORY)){
	    acpi_table_mem[acpi_table_index].mem_type = GRUB_ADDRESS_TYPE_ACPI;
	    acpi_table_mem[acpi_table_index].mem_start = (lsdesc->physical_start) & 0xffffffffffff;
	    acpi_table_mem[acpi_table_index].mem_size = lsdesc->num_pages * GRUB_EFI_PAGE_SIZE;
	    acpi_table_index++;
	}else if((lsdesc->type == GRUB_EFI_ACPI_MEMORY_NVS)){
	    acpi_nvs_mem[acpi_nvs_index].mem_type = GRUB_ADDRESS_TYPE_NVS;
	    acpi_nvs_mem[acpi_nvs_index].mem_start = (lsdesc->physical_start) & 0xffffffffffff;
	    acpi_nvs_mem[acpi_nvs_index].mem_size = lsdesc->num_pages * GRUB_EFI_PAGE_SIZE;
	    acpi_nvs_index++;

	/* Reserve */
	}else{
	    reserve_mem[reserve_index].mem_type = GRUB_ADDRESS_TYPE_RESERVED;
	    reserve_mem[reserve_index].mem_start = (lsdesc->physical_start) & 0xffffffffffff;
	    reserve_mem[reserve_index].mem_size = lsdesc->num_pages * GRUB_EFI_PAGE_SIZE;
	    reserve_index++;
	}
    }

  /*System RAM Sort*/
  tmp_index = grub_efi_loongarch64_memmap_sort(free_mem,
							free_index,
							loongson_mem_map,
							tmp_index,
							GRUB_ADDRESS_TYPE_SYSRAM);
  /*ACPI Sort*/
  tmp_index = grub_efi_loongarch64_memmap_sort(acpi_table_mem,
							acpi_table_index,
							loongson_mem_map,
							tmp_index,
							GRUB_ADDRESS_TYPE_ACPI);
  tmp_index = grub_efi_loongarch64_memmap_sort(acpi_nvs_mem,
							acpi_nvs_index,
							loongson_mem_map,
							tmp_index,
							GRUB_ADDRESS_TYPE_NVS);

  /*Reserve Sort*/
  tmp_index = grub_efi_loongarch64_memmap_sort (reserve_mem,
							reserve_index,
							loongson_mem_map,
							tmp_index,
							GRUB_ADDRESS_TYPE_RESERVED);

  loongson_mem_map->map_count = tmp_index;
  loongson_mem_map->header.checksum = 0;

  checksum = grub_kernel_update_checksum ((grub_uint8_t *) loongson_mem_map,
					  loongson_mem_map->header.length);
  loongson_mem_map->header.checksum = checksum;

  return grub_errno;
}
