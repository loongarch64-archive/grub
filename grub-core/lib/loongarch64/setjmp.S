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

#include <grub/symbol.h>
#include <grub/dl.h>
#include <grub/loongarch64/asm.h>

	.file	"setjmp.S"

GRUB_MOD_LICENSE "GPLv3+"

	.text

FUNCTION(grub_setjmp)
	GRUB_ASM_REG_S $s0, $a0,0
	GRUB_ASM_REG_S $s1, $a0,8
	GRUB_ASM_REG_S $s2, $a0,16
	GRUB_ASM_REG_S $s3, $a0,24
	GRUB_ASM_REG_S $s4, $a0,32
	GRUB_ASM_REG_S $s5, $a0,40
	GRUB_ASM_REG_S $s6, $a0,48
	GRUB_ASM_REG_S $s7, $a0,56
	GRUB_ASM_REG_S $s8, $a0,64
	GRUB_ASM_REG_S $fp, $a0,72
	GRUB_ASM_REG_S $sp, $a0,80
	GRUB_ASM_REG_S $ra, $a0,88
	move $v0, $zero
	move $v1, $zero
	jirl $zero,$ra,0

FUNCTION(grub_longjmp)
	GRUB_ASM_REG_L $s0, $a0,0
	GRUB_ASM_REG_L $s1, $a0,8
	GRUB_ASM_REG_L $s2, $a0,16
	GRUB_ASM_REG_L $s3, $a0,24
	GRUB_ASM_REG_L $s4, $a0,32
	GRUB_ASM_REG_L $s5, $a0,40
	GRUB_ASM_REG_L $s6, $a0,48
	GRUB_ASM_REG_L $s7, $a0,56
	GRUB_ASM_REG_L $s8, $a0,64
	GRUB_ASM_REG_L $fp, $a0,72
	GRUB_ASM_REG_L $sp, $a0,80
	GRUB_ASM_REG_L $ra, $a0,88
	addi.w $v0, $zero, 1
	bnez $a1, .ZW0
	addi.d $v0, $a1, 0
.ZW0:
	addi.d	$v1,$zero,0
	jirl $zero,$ra,0
