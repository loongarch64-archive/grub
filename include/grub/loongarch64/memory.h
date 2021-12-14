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

#ifndef GRUB_MEMORY_CPU_HEADER
#define GRUB_MEMORY_CPU_HEADER	1

#ifndef ASM_FILE
#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/types.h>
#endif

#ifndef ASM_FILE

typedef grub_addr_t grub_phys_addr_t;

static inline grub_phys_addr_t
grub_vtop (void *a)
{
  return ((grub_phys_addr_t) a) & 0xffffffffffffUL;
}

static inline void *
grub_map_memory (grub_phys_addr_t a, grub_size_t size)
{
  grub_uint64_t addr;
  asm volatile ("csrrd %0, 0x181" : "=r" (addr));
  return (void *) (a | (addr & 0xffffffffffffff00UL));
}

static inline void
grub_unmap_memory (void *a __attribute__ ((unused)),
		   grub_size_t size __attribute__ ((unused)))
{
}

#endif

#endif