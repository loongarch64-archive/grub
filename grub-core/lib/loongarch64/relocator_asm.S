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

#include <grub/symbol.h>

	.p2align	4

VARIABLE (grub_relocator_forward_start)

copycont1:
	ld.d	$r11, $r8,  0
	st.d	$r11, $r9,  0
	addi.d	$r8,  $r8,  8
	addi.d 	$r10, $r10, -8
	addi.d 	$r9,  $r9,  8
	bne    	$r10, $r0,  copycont1

VARIABLE (grub_relocator_forward_end)

VARIABLE (grub_relocator_backward_start)

	add.d	$r9, $r9, $r10
	add.d 	$r8, $r8, $r10
	addi.d	$r9, $r9, -8
	addi.d 	$r8, $r8, -8
copycont2:
	ld.w	$r11, $r8,   0
	st.w 	$r11, $r9,   0
	addi.d	$r8,  $r8,  -8
	addi.d 	$r10, $r10, -8
	addi.d 	$r9,  $r9,  -8
	bne	$r10, $r0,  copycont2

VARIABLE (grub_relocator_backward_end)
