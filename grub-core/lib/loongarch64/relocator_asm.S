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
  ld.d   $a7, $a4, 0
  st.d   $a7, $a5, 0
  addi.d $a4, $a4, 8
  addi.d $a6, $a6, -8
  addi.d $a5, $a5, 8
  bne    $a6, $zero, copycont1

VARIABLE (grub_relocator_forward_end)

VARIABLE (grub_relocator_backward_start)

  add.d  $a5, $a5, $a6
  add.d  $a4, $a4, $a6
  addi.d $a5, $a5, -8
  addi.d $a4, $a4, -8

copycont2:
  ld.w   $a7, $a4, 0
  st.w   $a7, $a5, 0
  addi.d $a4, $a4, -8
  addi.d $a6, $a6, -8
  addi.d $a5, $a5, -8
  bne    $a6, $zero, copycont2

VARIABLE (grub_relocator_backward_end)
