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

#include <grub/symbol.h>
#include <grub/dl.h>

	.file	"setjmp.S"

GRUB_MOD_LICENSE "GPLv3+"

	.text

FUNCTION(grub_setjmp)
	st.d $s0, $a0, 0
	st.d $s1, $a0, 8
	st.d $s2, $a0, 16
	st.d $s3, $a0, 24
	st.d $s4, $a0, 32
	st.d $s5, $a0, 40
	st.d $s6, $a0, 48
	st.d $s7, $a0, 56
	st.d $s8, $a0, 64
	st.d $fp, $a0, 72
	st.d $sp, $a0, 80
	st.d $ra, $a0, 88
	move $v0, $zero
	move $v1, $zero
	jirl $zero,$ra,0

FUNCTION(grub_longjmp)
	ld.d $s0, $a0,0
	ld.d $s1, $a0,8
	ld.d $s2, $a0,16
	ld.d $s3, $a0,24
	ld.d $s4, $a0,32
	ld.d $s5, $a0,40
	ld.d $s6, $a0,48
	ld.d $s7, $a0,56
	ld.d $s8, $a0,64
	ld.d $fp, $a0,72
	ld.d $sp, $a0,80
	ld.d $ra, $a0,88
	addi.w $v0, $zero, 1
	bnez $a1, .ZW0
	addi.d $v0, $a1, 0
.ZW0:
	addi.d	$v1,$zero,0
	jirl $zero,$ra,0
