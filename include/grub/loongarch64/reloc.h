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

#ifndef GRUB_LOONGARCH64_RELOC_H
#define GRUB_LOONGARCH64_RELOC_H 1

void grub_loongarch64_sop_push		     (grub_stack_t* stack,
					      grub_int64_t offset);
void grub_loongarch64_sop_sub		     (grub_stack_t* stack);
void grub_loongarch64_sop_sl		     (grub_stack_t* stack);
void grub_loongarch64_sop_sr		     (grub_stack_t* stack);
void grub_loongarch64_sop_add		     (grub_stack_t* stack);
void grub_loongarch64_sop_and		     (grub_stack_t* stack);
void grub_loongarch64_sop_if_else	     (grub_stack_t* stack);
void grub_loongarch64_sop_32_s_10_5	     (grub_stack_t* stack,
					      grub_uint64_t *place);
void grub_loongarch64_sop_32_u_10_12	     (grub_stack_t* stack,
					      grub_uint64_t *place);
void grub_loongarch64_sop_32_s_10_12	     (grub_stack_t* stack,
					      grub_uint64_t *place);
void grub_loongarch64_sop_32_s_10_16	     (grub_stack_t* stack,
					      grub_uint64_t *place);
void grub_loongarch64_sop_32_s_10_16_s2	     (grub_stack_t* stack,
					      grub_uint64_t *place);
void grub_loongarch64_sop_32_s_5_20	     (grub_stack_t* stack,
					      grub_uint64_t *place);
void grub_loongarch64_sop_32_s_0_5_10_16_s2  (grub_stack_t* stack,
					      grub_uint64_t *place);
void grub_loongarch64_sop_32_s_0_10_10_16_s2 (grub_stack_t* stack,
					      grub_uint64_t *place);
#endif /* GRUB_LOONGARCH64_RELOC_H */
