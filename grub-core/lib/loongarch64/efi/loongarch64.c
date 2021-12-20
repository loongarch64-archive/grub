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

#include <grub/mm.h>
#include <grub/cache.h>
#include <grub/efi/efi.h>
#include <grub/cpu/efi/memory.h>
#include <grub/cpu/memory.h>
#include <grub/machine/loongarch64.h>

static void *
grub_efi_loongarch64_get_smbios_table (void)
{
  struct bootparamsinterface* boot_params;
  void * tmp_boot_params = NULL;
  char * p = NULL;

  tmp_boot_params = grub_efi_loongarch64_get_boot_params();
  if(tmp_boot_params == NULL)
  {
    grub_dprintf("loongson", "tmp_boot_params is NULL\n");
    return NULL;
  }

  boot_params = (struct bootparamsinterface *)tmp_boot_params;
  p = (char *)&(boot_params->signature);
  if( grub_strncmp(p, "BPI", 3) == 0)
  {
    grub_dprintf("loongson", "find new bpi\n");
    return boot_params ? boot_params : NULL;
  }
  return tmp_boot_params;
}

int
grub_efi_is_loongarch64 (void)
{
  return grub_efi_loongarch64_get_smbios_table () ? 1 : 0;
}

void *
grub_efi_loongarch64_get_boot_params (void)
{
  static void * boot_params = NULL;
  grub_efi_configuration_table_t *tables;
  grub_efi_guid_t smbios_guid = GRUB_EFI_LOONGSON_SMBIOS_TABLE_GUID;
  unsigned int i;

  if (boot_params)
    return boot_params;

  /* Look for Loongson SMBIOS in UEFI config tables. */
  tables = grub_efi_system_table->configuration_table;

  for (i = 0; i < grub_efi_system_table->num_table_entries; i++)
    if (grub_memcmp (&tables[i].vendor_guid, &smbios_guid, sizeof (smbios_guid)) == 0)
      {
        boot_params= tables[i].vendor_table;
        grub_dprintf ("loongson", "found registered SMBIOS @ %p\n", boot_params);
        break;
      }
  return boot_params;
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
grub_efi_loongarch64_memmap_sort(struct memmap array[], grub_uint32_t length, mem_map * bpmem, grub_uint32_t index, grub_uint32_t memtype)
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
