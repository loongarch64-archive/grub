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

#include <grub/symbol.h>

	.file 	"startup.S"
	.text

	.align		4

FUNCTION(_start)
	addi.d		$sp, $sp, -16
	st.d		$ra, $sp, 0

	la 		$a2, grub_efi_image_handle
	st.d		$a0, $a2, 0
	la		$a2, grub_efi_system_table
	st.d		$a1, $a2, 0

	bl		grub_main

1:
	ld.d		$ra, $sp, 0
	addi.d		$sp, $sp, 16
	jirl 		$zero, $ra, 0
