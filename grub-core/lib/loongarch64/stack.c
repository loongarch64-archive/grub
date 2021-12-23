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

#include <grub/cpu/stack.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/dl.h>

struct grub_loongarch64_stack
{
  grub_uint64_t *data;
  int count;
  int top;
};

grub_loongarch64_stack_t grub_loongarch64_stack_new  (int n)
{
  grub_loongarch64_stack_t stack;

  stack = (grub_loongarch64_stack_t) grub_malloc(sizeof(struct grub_loongarch64_stack));
  stack->data = (grub_uint64_t*) grub_malloc (n * sizeof (grub_uint64_t));
  stack->count = n;
  stack->top = -1;
  return stack;
}

void grub_loongarch64_stack_push (grub_loongarch64_stack_t stack, grub_uint64_t x)
{
  if (stack->top == stack->count)
    return;
  stack->data[++stack->top] = x;
}

grub_uint64_t grub_loongarch64_stack_pop (grub_loongarch64_stack_t stack)
{
  if (stack->top == -1)
    return -1;
  return stack->data[stack->top--];
}

grub_uint64_t grub_loongarch64_stack_peek (grub_loongarch64_stack_t stack)
{
  if (stack->top == -1)
    return -1;
  return stack->data[stack->top];
}

void grub_loongarch64_stack_display (grub_loongarch64_stack_t stack)
{
  for(int i=stack->top ; i>-1 ; i--)
    grub_dprintf("stack:", "%"PRIuGRUB_UINT64_T" ",stack->data[i]);
  grub_dprintf("stack:", "\n\n");
}

void grub_loongarch64_stack_destroy (grub_loongarch64_stack_t stack)
{
  grub_free(stack->data);
  grub_free(stack);
}
