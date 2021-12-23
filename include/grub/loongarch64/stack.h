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

#ifndef GRUB_STACK_HEADER
#define GRUB_STACK_HEADER 1

#include <grub/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct grub_loongarch64_stack;
typedef struct grub_loongarch64_stack* grub_loongarch64_stack_t;

grub_loongarch64_stack_t  grub_loongarch64_stack_new     (int count);
void                      grub_loongarch64_stack_push    (grub_loongarch64_stack_t stack, grub_uint64_t x);
grub_uint64_t             grub_loongarch64_stack_pop     (grub_loongarch64_stack_t stack);
grub_uint64_t             grub_loongarch64_stack_peek    (grub_loongarch64_stack_t stack);
void                      grub_loongarch64_stack_display (grub_loongarch64_stack_t stack);
void                      grub_loongarch64_stack_destroy (grub_loongarch64_stack_t stack);

#ifdef __cplusplus
}
#endif

#endif /* GRUB_STACK_HEADER */
