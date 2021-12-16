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

#ifndef KERNEL_CPU_TIME_HEADER
#define KERNEL_CPU_TIME_HEADER	1

#ifndef GRUB_UTIL

#define GRUB_TICKS_PER_SECOND	(grub_arch_cpuclock / 2)

void grub_timer_init (grub_uint32_t cpuclock);

extern grub_uint32_t grub_arch_cpuclock;
#endif

static inline void
grub_cpu_idle(void)
{
  __asm__ __volatile__("idle 0\n");
}

#endif
