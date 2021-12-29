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
/* Used to support ELF linux kernel */

#include <grub/mm.h>
#include <grub/misc.h>

#include <grub/types.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/cache.h>

#include <grub/loongarch64/relocator.h>
#include <grub/relocator_private.h>

extern grub_uint8_t grub_relocator_forward_start;
extern grub_uint8_t grub_relocator_forward_end;
extern grub_uint8_t grub_relocator_backward_start;
extern grub_uint8_t grub_relocator_backward_end;

#define REGW_SIZEOF (4 * sizeof (grub_uint32_t))
#define JUMP_SIZEOF (1 * sizeof (grub_uint32_t))

#define RELOCATOR_SRC_SIZEOF(x) (&grub_relocator_##x##_end \
				 - &grub_relocator_##x##_start)
#define RELOCATOR_SIZEOF(x)	(RELOCATOR_SRC_SIZEOF(x) \
				 + REGW_SIZEOF * 3)
#define INS_LU12I_W 0x14000000
#define INS_ORI     0x03800000
#define INS_LU32I_D 0x16000000
#define INS_LU52I_D 0x3000000
#define INS_JIRL    0x4c000000
#define REG_RA 1
#define REG_A4 8
#define REG_A5 9
#define REG_A6 10

grub_size_t grub_relocator_align = sizeof (grub_uint64_t);
grub_size_t grub_relocator_forward_size;
grub_size_t grub_relocator_backward_size;
grub_size_t grub_relocator_jumper_size = JUMP_SIZEOF + REGW_SIZEOF;

void
grub_cpu_relocator_init (void)
{
  grub_relocator_forward_size = RELOCATOR_SIZEOF(forward);
  grub_relocator_backward_size = RELOCATOR_SIZEOF(backward);
}

static void
write_reg (int regn, grub_uint64_t val, void **target)
{

  *(grub_uint32_t *) *target = (INS_LU12I_W | (grub_uint32_t)((val & 0xfffff000)>>12<<5) | (grub_uint32_t)regn);;
  *target = ((grub_uint32_t *) *target) + 1;
  *(grub_uint32_t *) *target = (INS_ORI | (grub_uint32_t)((val & 0xfff)<<10) | (grub_uint32_t)(regn | regn<<5));
  *target = ((grub_uint32_t *) *target) + 1;
  *(grub_uint32_t *) *target = (INS_LU32I_D | (grub_uint32_t)((val & 0xfffff00000000)>>32<<5) | (grub_uint32_t)regn);;
  *target = ((grub_uint32_t *) *target) + 1;
  *(grub_uint32_t *) *target = (INS_LU52I_D | (grub_uint32_t)((val & 0xfff0000000000000)>>52<<10) | (grub_uint32_t)(regn | regn<<5));;
  *target = ((grub_uint32_t *) *target) + 1;
}

static void
write_jump (int regn, void **target)
{
  *(grub_uint32_t *) *target = (INS_JIRL | (grub_uint32_t)(regn<<5));
  *target = ((grub_uint32_t *) *target) + 1;
}

void
grub_cpu_relocator_jumper (void *rels, grub_addr_t addr)
{
  write_reg (REG_RA, addr, &rels);
  write_jump (REG_RA, &rels);
}

void
grub_cpu_relocator_backward (void *ptr0, void *src, void *dest,
			     grub_size_t size)
{
  void *ptr = ptr0;
  write_reg (REG_A4, (grub_uint64_t) src, &ptr);
  write_reg (REG_A5, (grub_uint64_t) dest, &ptr);
  write_reg (REG_A6, (grub_uint64_t) size, &ptr);
  grub_memcpy (ptr, &grub_relocator_backward_start,
	       RELOCATOR_SRC_SIZEOF (backward));
}

void
grub_cpu_relocator_forward (void *ptr0, void *src, void *dest,
			    grub_size_t size)
{
  void *ptr = ptr0;
  write_reg (REG_A4, (grub_uint64_t) src, &ptr);
  write_reg (REG_A5, (grub_uint64_t) dest, &ptr);
  write_reg (REG_A6, (grub_uint64_t) size, &ptr);
  grub_memcpy (ptr, &grub_relocator_forward_start,
	       RELOCATOR_SRC_SIZEOF (forward));
}

grub_err_t
grub_relocator64_boot (struct grub_relocator *rel,
		       struct grub_relocator64_state state)
{
  grub_relocator_chunk_t ch;
  void *ptr;
  grub_err_t err;
  void *relst;
  grub_size_t relsize;
  grub_size_t stateset_size = 31 * REGW_SIZEOF + JUMP_SIZEOF;
  unsigned i;
  grub_addr_t vtarget;

  err = grub_relocator_alloc_chunk_align (rel, &ch, 0,
					  (0xffffffff - stateset_size)
					  + 1, stateset_size,
					  grub_relocator_align,
					  GRUB_RELOCATOR_PREFERENCE_NONE, 0);
  if (err)
    return err;

  ptr = get_virtual_current_address (ch);
  for (i = 1; i < 32; i++)
    write_reg (i, state.gpr[i], &ptr);
  write_jump (state.jumpreg, &ptr);

  vtarget = (grub_addr_t) grub_map_memory (get_physical_target_address (ch),
					   stateset_size);

  err = grub_relocator_prepare_relocs (rel, vtarget, &relst, &relsize);
  if (err)
    return err;

  grub_arch_sync_caches ((void *) relst, relsize);

  grub_uint64_t val;
  __asm__ __volatile__("li.w      %0, 0x4\n\t"
		       "csrxchg $r0, %0, 0x0\n\t"
		       : "=r"(val));

  ((void (*) (void)) relst) ();

  /* Not reached.  */
  return GRUB_ERR_NONE;
}
