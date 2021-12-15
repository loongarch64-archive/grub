/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2021  Loongson Technology Corporation Limited, 
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
#include <grub/machine/loongarch64.h>
#include <grub/memory.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>
#include <grub/linux.h>

GRUB_MOD_LICENSE ("GPLv3+");

#pragma GCC diagnostic ignored "-Wcast-align"

typedef  unsigned long size_t;

static grub_dl_t my_mod;

static int loaded;

static grub_uint32_t tmp_index = 0;
static grub_size_t linux_size;

static struct grub_relocator *relocator;
static grub_addr_t target_addr, entry_addr;
static int linux_argc;
static grub_uint8_t *linux_args_addr;
static grub_off_t rd_addr_arg_off, rd_size_arg_off;
static grub_off_t initrd_addr_arg_off;
static int initrd_loaded = 0;

static grub_uint32_t j = 0;
static grub_uint32_t t = 0;
grub_uint64_t tempMemsize = 0;
grub_uint32_t free_index = 0;
grub_uint32_t reserve_index = 0;
grub_uint32_t acpi_table_index = 0;
grub_uint32_t acpi_nvs_index = 0;

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

static grub_err_t
grub_linux_boot (void)
{
  struct grub_relocator64_state state;
  grub_int8_t checksum = 0;
  grub_efi_memory_descriptor_t * lsdesc = NULL;

  grub_memset (&state, 0, sizeof (state));

  /* Boot the kernel.  */
  state.gpr[1] = entry_addr;
  state.gpr[4] = linux_argc;
  state.gpr[5] = (grub_addr_t) linux_args_addr;

  if(grub_efi_is_loongarch64 ())
  {
    grub_efi_uintn_t mmap_size;
    grub_efi_uintn_t desc_size;
    grub_efi_memory_descriptor_t *mmap_buf;
    grub_err_t err;
    struct bootparamsinterface * boot_params;
    void * tmp_boot_params = NULL;
    grub_efi_uint8_t new_interface_flag = 0;
    mem_map * new_interface_mem = NULL;
    char *p = NULL;

    struct memmap reserve_mem[GRUB_EFI_LOONGSON_MMAP_MAX];
    struct memmap free_mem[GRUB_EFI_LOONGSON_MMAP_MAX];
    struct memmap acpi_table_mem[GRUB_EFI_LOONGSON_MMAP_MAX];
    struct memmap acpi_nvs_mem[GRUB_EFI_LOONGSON_MMAP_MAX];
    
    grub_memset(reserve_mem, 0, sizeof(struct memmap) * GRUB_EFI_LOONGSON_MMAP_MAX);
    grub_memset(free_mem, 0, sizeof(struct memmap) * GRUB_EFI_LOONGSON_MMAP_MAX);
    grub_memset(acpi_table_mem, 0, sizeof(struct memmap) * GRUB_EFI_LOONGSON_MMAP_MAX);
    grub_memset(acpi_nvs_mem, 0, sizeof(struct memmap) * GRUB_EFI_LOONGSON_MMAP_MAX);

    tmp_boot_params = grub_efi_loongarch64_get_boot_params();
    if(tmp_boot_params == NULL)
    {
      grub_printf("not find param\n");
      return -1;
    }

    boot_params = (struct bootparamsinterface *)tmp_boot_params;
    p = (char *)&(boot_params->signature);
    if(grub_strncmp(p, "BPI", 3) == 0)
    {
      /* Check extlist headers */
      ext_list * listpointer = NULL;
      listpointer = boot_params->extlist;
      for( ;listpointer != NULL; listpointer = listpointer->next)
      {
        char *pl= (char *)&(listpointer->signature);
        if(grub_strncmp(pl, "MEM", 3) == 0)
        {
          new_interface_mem = (mem_map *)listpointer;
        }
      }

      new_interface_flag = 1;
      grub_dprintf("loongson", "get new parameter interface\n");
    }else{
      new_interface_flag = 0;
      grub_dprintf("loongson", "get old parameter interface\n");
    }

    state.gpr[6] = (grub_uint64_t)tmp_boot_params;
    mmap_size = find_mmap_size ();
    if (! mmap_size)
      return grub_errno;
    mmap_buf = grub_efi_allocate_any_pages (page_align (mmap_size) >> 12);
    if (! mmap_buf)
      return grub_error (GRUB_ERR_IO, "cannot allocate memory map");
    err = grub_efi_finish_boot_services (&mmap_size, mmap_buf, NULL,
                                         &desc_size, NULL);
    if (err)
      return err;

    if(new_interface_flag)
    {
      if (!mmap_buf || !mmap_size || !desc_size)
        return -1;
      tmp_index = new_interface_mem -> mapcount;

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
          free_mem[free_index].memtype = GRUB_EFI_LOONGSON_SYSTEM_RAM;
          free_mem[free_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
          free_mem[free_index].memsize = lsdesc->num_pages * 4096;
          free_index++;

        /*ACPI*/
        }else if((lsdesc->type == GRUB_EFI_ACPI_RECLAIM_MEMORY)){
          acpi_table_mem[acpi_table_index].memtype = GRUB_EFI_LOONGSON_ACPI_TABLE;
          acpi_table_mem[acpi_table_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
          acpi_table_mem[acpi_table_index].memsize = lsdesc->num_pages * 4096;
          acpi_table_index++;
        }else if((lsdesc->type == GRUB_EFI_ACPI_MEMORY_NVS)){
          acpi_nvs_mem[acpi_nvs_index].memtype = GRUB_EFI_LOONGSON_ACPI_NVS;
          acpi_nvs_mem[acpi_nvs_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
          acpi_nvs_mem[acpi_nvs_index].memsize = lsdesc->num_pages * 4096;
          acpi_nvs_index++;

        /* Reserve */
        }else{
          reserve_mem[reserve_index].memtype = GRUB_EFI_LOONGSON_MEMORY_RESERVED;
          reserve_mem[reserve_index].memstart = (lsdesc->physical_start) & 0xffffffffffff;
          reserve_mem[reserve_index].memsize = lsdesc->num_pages * 4096;
          reserve_index++;
        }
      }

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

        new_interface_mem->map[tmp_index].memtype = GRUB_EFI_LOONGSON_SYSTEM_RAM;
        new_interface_mem->map[tmp_index].memstart = free_mem[j].memstart;
        new_interface_mem->map[tmp_index].memsize = tempMemsize;
        grub_dprintf("loongson", "map[%d]:type %x, start 0x%llx, end 0x%llx\n",
                     tmp_index,
                     new_interface_mem->map[tmp_index].memtype,
                     new_interface_mem->map[tmp_index].memstart,
                     new_interface_mem->map[tmp_index].memstart+ new_interface_mem->map[tmp_index].memsize
                    );
        j = t;
        tmp_index++;
      }
      /*ACPI Sort*/
      //tmp_index = grub_efi_loongson_memmap_sort(acpi_table_mem, acpi_table_index, new_interface_mem, tmp_index, GRUB_EFI_LOONGSON_ACPI_TABLE);
      //tmp_index = grub_efi_loongson_memmap_sort(acpi_nvs_mem, acpi_nvs_index, new_interface_mem, tmp_index, GRUB_EFI_LOONGSON_ACPI_NVS);
      /*Reserve Sort*/
	  grub_uint64_t loongarch_addr;
	  asm volatile ("csrrd %0, 0x181" : "=r" (loongarch_addr));
	  if((loongarch_addr & 0xff00000000000000) == 0x9000000000000000){
        tmp_index = grub_efi_loongarch64_memmap_sort(reserve_mem, reserve_index, new_interface_mem, tmp_index, GRUB_EFI_LOONGSON_MEMORY_RESERVED);
	  }else{
        tmp_index = grub_efi_loongarch64_memmap_sort(reserve_mem, reserve_index, new_interface_mem, tmp_index, GRUB_EFI_LOONGSON_MEMORY_RESERVED + 1);
	  }

      new_interface_mem->mapcount = tmp_index;
      new_interface_mem->header.checksum = 0;

      checksum = grub_efi_loongarch64_grub_calculatechecksum8(new_interface_mem, new_interface_mem->header.length);
      new_interface_mem->header.checksum = checksum;
    }
  }

  state.jumpreg = 1;
  grub_relocator64_boot (relocator, state);

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
grub_linux_load32 (grub_elf_t elf, const char *filename)
{
  Elf32_Addr base;
  grub_err_t err;
  grub_uint8_t *playground;

  /* Linux's entry point incorrectly contains a virtual address.  */
  entry_addr = elf->ehdr.ehdr32.e_entry;

  linux_size = grub_elf32_size (elf, &base, 0);
  if (linux_size == 0)
    return grub_errno;
  target_addr = base;
  linux_size = ALIGN_UP (base + linux_size - base, 8);

  relocator = grub_relocator_new ();
  if (!relocator)
    return grub_errno;

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					   grub_vtop ((void *) target_addr),
					   linux_size);
    if (err)
      return err;
    playground = get_virtual_current_address (ch);
  }

  /* Now load the segments into the area we claimed.  */
  return grub_elf32_load (elf, filename, playground - base, GRUB_ELF_LOAD_FLAGS_NONE, 0, 0);
}

static grub_err_t
grub_linux_load64 (grub_elf_t elf, const char *filename)
{
  Elf64_Addr base;
  grub_err_t err;
  grub_uint8_t *playground;

  /* Linux's entry point incorrectly contains a virtual address.  */
  entry_addr = elf->ehdr.ehdr64.e_entry;
  linux_size = grub_elf64_size (elf, &base, 0);

  if (linux_size == 0)
    return grub_errno;
  target_addr = base;
  linux_size = ALIGN_UP (base + linux_size - base, 8);

  relocator = grub_relocator_new ();
  if (!relocator)
    return grub_errno;

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					   grub_vtop ((void *) target_addr),
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

  if (grub_elf_is_elf32 (elf))
    err = grub_linux_load32 (elf, argv[0]);
  else
  if (grub_elf_is_elf64 (elf))
    err = grub_linux_load64 (elf, argv[0]);
  else
    err = grub_error (GRUB_ERR_BAD_OS, N_("invalid arch-dependent ELF magic"));

  grub_elf_close (elf);

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

  linux_argv = (grub_uint64_t *) linux_args_addr;
  linux_args = (char *) (linux_argv + (linux_argc + 1 + 3));

  grub_memcpy (linux_args, "a0", sizeof ("a0"));
  *linux_argv = (grub_uint64_t) (grub_addr_t) linux_args;
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
  initrd_loaded = 0;
  loaded = 1;
  grub_dl_ref (my_mod);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)),
		 int argc, char *argv[])
{
  grub_size_t size = 0;
  void *initrd_dest;
  grub_err_t err;
  struct grub_linux_initrd_context initrd_ctx = { 0, 0, 0 };

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  if (!loaded)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("you need to load the kernel first"));

  if (initrd_loaded)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "only one initrd command can be issued.");

  if (grub_initrd_init (argc, argv, &initrd_ctx))
    goto fail;

  size = grub_get_initrd_size (&initrd_ctx);

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_align (relocator, &ch,
					    0, (0xffffffff - size) + 1,
					    size, 0x10000,
					    GRUB_RELOCATOR_PREFERENCE_LOW, 0);

    if (err)
      goto fail;
    initrd_dest = get_virtual_current_address (ch);
  }

  if (grub_initrd_load (&initrd_ctx, argv, initrd_dest))
    goto fail;

  grub_snprintf ((char *) linux_args_addr + rd_addr_arg_off,
		 sizeof ("rd_start=0xXXXXXXXXXXXXXXXX"), "rd_start=0x%lx",
		(grub_uint64_t) initrd_dest);
  ((grub_uint64_t *) linux_args_addr)[linux_argc]
    = (grub_uint64_t) ((grub_addr_t) linux_args_addr + rd_addr_arg_off);
  linux_argc++;

  grub_snprintf ((char *) linux_args_addr + rd_size_arg_off,
		sizeof ("rd_size=0xXXXXXXXXXXXXXXXXX"), "rd_size=0x%lx",
		(grub_uint64_t) size);
  ((grub_uint64_t *) linux_args_addr)[linux_argc]
    = (grub_uint64_t) ((grub_addr_t) linux_args_addr + rd_size_arg_off);
  linux_argc++;


  grub_snprintf ((char *) linux_args_addr + initrd_addr_arg_off,
		 sizeof ("initrd=0xXXXXXXXXXXXXXXXX,0xXXXXXXXXXXXXXXXX"), "initrd=0x%lx,0x%lx",
		((grub_uint64_t) initrd_dest & 0xffffffff), (grub_uint64_t) size);
  ((grub_uint64_t *) linux_args_addr)[linux_argc]
    = (grub_uint64_t) ((grub_addr_t) linux_args_addr + initrd_addr_arg_off);
  linux_argc++;

  initrd_loaded = 1;

 fail:
  grub_initrd_close (&initrd_ctx);

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
