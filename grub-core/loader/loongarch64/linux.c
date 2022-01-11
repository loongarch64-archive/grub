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

#include <grub/loader.h>
#include <grub/misc.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>
#include <grub/linux.h>
#include <grub/cpu/linux.h>
#include <grub/efi/memory.h>

GRUB_MOD_LICENSE ("GPLv3+");

static struct linux_loongarch64_kernel_params kernel_params;

static grub_addr_t phys_addr;
static grub_dl_t my_mod;
static int loaded;
static int grub_loongarch_linux_type = GRUB_LOONGARCH_LINUX_BAD;

static grub_err_t
grub_linux_boot (void)
{

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_EFI) {
      return (grub_arch_efi_linux_boot_image((grub_addr_t) kernel_params.kernel_addr,
					     kernel_params.kernel_size,
					     kernel_params.linux_args));
  }
  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_ELF) {
      return grub_linux_loongarch_elf_linux_boot_image (&kernel_params);
  }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_linux_unload (void)
{

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_EFI) {
      if (kernel_params.ramdisk_addr)
	grub_efi_free_pages ((grub_efi_physical_address_t) kernel_params.ramdisk_addr,
			     GRUB_EFI_BYTES_TO_PAGES (kernel_params.ramdisk_size));
      kernel_params.ramdisk_size = 0;

      if (kernel_params.kernel_addr)
	grub_efi_free_pages ((grub_addr_t) kernel_params.kernel_addr,
			     GRUB_EFI_BYTES_TO_PAGES (kernel_params.kernel_size));
      kernel_params.kernel_addr = 0;
  }

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_ELF) {
      grub_free (kernel_params.linux_args);
      kernel_params.linux_args = 0;
      grub_linux_loongarch_elf_relocator_unload ();
  }

  grub_dl_unref (my_mod);
  loaded = 0;
  grub_loongarch_linux_type = GRUB_LOONGARCH_LINUX_BAD;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_linux_loongarch_elf_load_kernel (grub_elf_t elf, const char *filename)
{
  Elf64_Addr base;
  grub_err_t err;
  grub_uint8_t *playground;
  int flag;

  /* Linux's entry point incorrectly contains a virtual address.  */
  kernel_params.kernel_addr = elf->ehdr.ehdr64.e_entry;
  kernel_params.kernel_size = grub_elf64_size (elf, &base, 0);

  if (kernel_params.kernel_size == 0)
    return grub_errno;

  phys_addr = base;
  kernel_params.kernel_size = ALIGN_UP (base + kernel_params.kernel_size - base, 8);

  if (kernel_params.kernel_addr & ELF64_LOADMASK) {
    flag = GRUB_ELF_LOAD_FLAGS_30BITS;
    base &= ~ELF64_LOADMASK;
    kernel_params.kernel_addr &= ~ELF64_LOADMASK;
  } else {
    flag = GRUB_ELF_LOAD_FLAGS_NONE;
  }

  playground = grub_linux_loongarch_alloc_virtual_mem_addr (phys_addr,
							    kernel_params.kernel_size,
							    &err);
  if (playground == NULL)
    return err;

  /* Now load the segments into the area we claimed.  */
  return grub_elf64_load (elf, filename, playground - base,
			  flag, 0, 0);
}

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_file_t file = 0;
  struct linux_arch_kernel_header lh;
  grub_elf_t elf = NULL;
  grub_err_t err;
  grub_size_t cmdline_size;
  int i;

  grub_dl_ref (my_mod);

  /* Release the previously used memory.  */
  grub_loader_unset ();

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  file = grub_file_open (argv[0], GRUB_FILE_TYPE_LINUX_KERNEL);
  if (!file)
    goto fail;

  kernel_params.kernel_size = grub_file_size (file);
  grub_dprintf ("linux", "kernel file size: %" PRIuGRUB_SIZE "\n",
		kernel_params.kernel_size);

  /* check linux kernel type */
  elf = grub_elf_file (file, argv[0]);
  if (elf != NULL)
    {
      /* linux kernel type is ELF */
      grub_loongarch_linux_type = GRUB_LOONGARCH_LINUX_ELF;
      if (elf->ehdr.ehdr64.e_type != ET_EXEC)
	{
	  grub_error (GRUB_ERR_UNKNOWN_OS,
		      N_("this ELF file is not of the right type"));
	  goto fail;
	}
      if (elf->ehdr.ehdr64.e_machine != EM_LOONGARCH)
	{
	  grub_error (GRUB_ERR_BAD_OS, "invalid magic number");
	  goto fail;
	}

      if (grub_elf_is_elf64 (elf))
	{
	  err = grub_linux_loongarch_elf_load_kernel (elf, argv[0]);
	  if (err)
	    goto fail;
	} else {
	    grub_error (GRUB_ERR_BAD_OS, N_("invalid arch-dependent ELF magic"));
	    goto fail;
	}
      grub_dprintf ("linux", "kernel @ %p\n", (void*) elf->ehdr.ehdr64.e_entry);
    }

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_BAD)
    {
      if (grub_file_seek (file, 0) == (grub_off_t) -1)
	goto fail;

      if (grub_file_read (file, &lh, sizeof (lh)) < (grub_ssize_t) sizeof (lh))
	{
	  if (!grub_errno)
	    grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
			argv[0]);
	  goto fail;
	}

      if (grub_arch_efi_linux_check_image (&lh) != GRUB_ERR_NONE)
	{
	  goto fail;
	}
      /* linux kernel type is EFI */
      grub_loongarch_linux_type = GRUB_LOONGARCH_LINUX_EFI;
      kernel_params.kernel_addr = (grub_addr_t) grub_efi_allocate_any_pages (
				GRUB_EFI_BYTES_TO_PAGES (kernel_params.kernel_size));
      grub_dprintf ("linux", "kernel numpages: %" PRIuGRUB_SIZE "\n",
		    GRUB_EFI_BYTES_TO_PAGES (kernel_params.kernel_size));
      if (!kernel_params.kernel_addr)
	{
	  grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
	  goto fail;
	}

      grub_file_seek (file, 0);
      if (grub_file_read (file, (void*) kernel_params.kernel_addr, kernel_params.kernel_size)
	  < (grub_int64_t) kernel_params.kernel_size)
	{
	  if (!grub_errno)
	    grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"), argv[0]);
	  goto fail;
	}

      grub_dprintf ("linux", "kernel @ %p\n", (void*) kernel_params.kernel_addr);
    }

  cmdline_size = grub_loader_cmdline_size (argc, argv) + sizeof (LINUX_IMAGE);
  kernel_params.linux_argc = argc;
  kernel_params.linux_args = grub_malloc (cmdline_size);
  if (!kernel_params.linux_args)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }

  grub_memcpy (kernel_params.linux_args, LINUX_IMAGE, sizeof (LINUX_IMAGE));

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_EFI)
    {
      err = grub_create_loader_cmdline (argc, argv,
					(char*) ((grub_addr_t) kernel_params.linux_args + sizeof (LINUX_IMAGE) - 1),
					cmdline_size,
					GRUB_VERIFY_KERNEL_CMDLINE);
      if (err)
	goto fail;

    }

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_ELF) {
      /* save args from linux cmdline */
      char *p = kernel_params.linux_args;
      p += sizeof (LINUX_IMAGE) - 1;
      for (i=0; i < argc; i++)
	{
	  grub_memcpy (p, argv[i], grub_strlen(argv[i]) + 1);
	  p += grub_strlen(argv[i]) + 1;
	}
  }

  if (grub_errno == GRUB_ERR_NONE)
    {
      grub_loader_set (grub_linux_boot, grub_linux_unload, 0);
      loaded = 1;
    }

fail:
  if (elf != NULL) {
      /* grub_elf_close will call grub_file_close() */
      grub_elf_close (elf);
  } else {
      if (file)
	grub_file_close (file);
  }

  if (grub_errno != GRUB_ERR_NONE)
    {
      grub_dl_unref (my_mod);
      loaded = 0;
    }

  if (kernel_params.linux_args && !loaded)
    grub_free (kernel_params.linux_args);

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_EFI) {
      if (kernel_params.kernel_addr && !loaded)
	grub_efi_free_pages ((grub_addr_t) kernel_params.kernel_addr,
			     GRUB_EFI_BYTES_TO_PAGES (kernel_params.kernel_size));
  }

  return grub_errno;
}

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

  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_EFI) {
      grub_size_t initrd_pages;
      initrd_pages = (GRUB_EFI_BYTES_TO_PAGES (initrd_size));
      initrd_mem = grub_linux_loongarch_efi_allocate_initrd_mem (initrd_pages);
  } else {
      grub_err_t err;
      initrd_mem = grub_linux_loongarch_alloc_virtual_mem_align (initrd_size, 0x10000, &err);
      if (err)
	goto fail;
  }

  if (!initrd_mem)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto fail;
    }

  if (grub_initrd_load (&initrd_ctx, argv, initrd_mem))
    goto fail;

  /* save ramdisk addr and size */
  kernel_params.ramdisk_addr = (grub_addr_t) initrd_mem;
  kernel_params.ramdisk_size = initrd_size;
  grub_dprintf ("linux", "ramdisk [addr=%p, size=0x%lx]\n",
		(void *) initrd_mem, initrd_size);
fail:
  grub_initrd_close (&initrd_ctx);
  if (grub_loongarch_linux_type == GRUB_LOONGARCH_LINUX_EFI) {
      if (initrd_mem && !kernel_params.ramdisk_addr)
	grub_efi_free_pages ((grub_addr_t) initrd_mem,
			     GRUB_EFI_BYTES_TO_PAGES (initrd_size));
  }
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
