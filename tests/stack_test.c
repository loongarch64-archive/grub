/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <string.h>
#include <grub/test.h>
#include <grub/misc.h>
#include <grub/loongarch64/stack.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void
stack_queue_test (void)
{
  grub_stack_t stack;

  stack = grub_stack_new (10);

  grub_stack_push (stack, 1);
  grub_stack_push (stack, 2);
  grub_stack_push (stack, 3);
  grub_stack_push (stack, 4);

  grub_stack_display (stack);

  if ( grub_stack_peek (stack) != 4 ) {
      grub_test_assert (0, "stack: peek failed");
  }
  if ( grub_stack_pop (stack) != 4) {
      grub_test_assert (0, "stack: pop failed");
  }
  if ( grub_stack_pop (stack) != 3) {
      grub_test_assert (0, "stack: pop failed");
  }
  grub_stack_pop (stack);

  grub_stack_display (stack);

  grub_stack_destroy (stack);
}

GRUB_UNIT_TEST ("stack_unit_test", stack_queue_test);
