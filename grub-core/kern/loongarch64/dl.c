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

#include <grub/dl.h>
#include <grub/elf.h>
#include <grub/misc.h>
#include <grub/err.h>
#include <grub/cpu/types.h>
#include <grub/mm.h>
#include <grub/i18n.h>

#define RELOC_STACK_MAX 1024

/* Check if EHDR is a valid ELF header.  */
grub_err_t
grub_arch_dl_check_header (void *ehdr)
{
  Elf_Ehdr *e = ehdr;

  /* Check the magic numbers.  */
  if (e->e_ident[EI_CLASS] != ELFCLASS64
      || e->e_ident[EI_DATA] != ELFDATA2LSB || e->e_machine != EM_LOONGARCH)
    return grub_error (GRUB_ERR_BAD_OS, N_("invalid arch-dependent ELF magic"));

  return GRUB_ERR_NONE;
}

#pragma GCC diagnostic ignored "-Wcast-align"

/* Relocate symbols.  */
grub_err_t
grub_arch_dl_relocate_symbols (grub_dl_t mod, void *ehdr,
			       Elf_Shdr *s, grub_dl_segment_t seg)
{
  Elf_Rel *rel, *max;
  grub_uint64_t oprs[RELOC_STACK_MAX]={0};
  int opri=-1;
  grub_uint32_t la_abs = 0;

  for (rel = (Elf_Rel *) ((char *) ehdr + s->sh_offset),
	 max = (Elf_Rel *) ((char *) rel + s->sh_size);
       rel < max;
       rel = (Elf_Rel *) ((char *) rel + s->sh_entsize))
    {
      Elf_Sym *sym;
      grub_uint8_t *place;
      grub_uint64_t sym_addr;

      if (rel->r_offset >= seg->size)
	return grub_error (GRUB_ERR_BAD_MODULE,
			   "reloc offset is out of the segment");

      sym = (Elf_Sym *) ((char*)mod->symtab
			 + mod->symsize * ELF_R_SYM (rel->r_info));

      sym_addr = sym->st_value;
      if (s->sh_type == SHT_RELA)
	sym_addr += ((Elf_Rela *) rel)->r_addend;
      place = (grub_uint8_t *) ((char*)seg->addr + rel->r_offset);
      switch (ELF_R_TYPE (rel->r_info))
	{
	case R_LARCH_64:
	  {
	    *(grub_uint64_t *)place=(grub_uint64_t)sym_addr;
	  }
	break;
	case R_LARCH_MARK_LA:
	  {
	    la_abs=1;
	  }
	break;
	case R_LARCH_SOP_PUSH_PCREL:
	  {
	    opri++;
	    oprs[opri]=(grub_uint64_t)(sym_addr-(grub_uint64_t)place);
	  }
	break;
	case R_LARCH_SOP_PUSH_ABSOLUTE:
	  {
	    opri++;
	    oprs[opri]=(grub_uint64_t)sym_addr;
	  }
	break;
	case R_LARCH_SOP_PUSH_PLT_PCREL:
	  {
	    opri++;
	    oprs[opri]=(grub_uint64_t)(sym_addr-(grub_uint64_t)place);
	  }
	  break;
	case R_LARCH_SOP_SUB:
	  {
	    grub_uint64_t opr2=oprs[opri];
	    opri--;
	    grub_uint64_t opr1=oprs[opri];
	    opri--;
	    opri++;
	    oprs[opri]=opr1 - opr2;
	  }
	  break;
	case R_LARCH_SOP_SL:
	  {
	    grub_uint64_t opr2=oprs[opri];
	    opri--;
	    grub_uint64_t opr1=oprs[opri];
	    opri--;
	    opri++;
	    oprs[opri]=opr1 << opr2;
	  }
	  break;
	case R_LARCH_SOP_SR:
	  {
	    grub_uint64_t opr2=oprs[opri];
	    opri--;
	    grub_uint64_t opr1=oprs[opri];
	    opri--;
	    opri++;
	    oprs[opri]=opr1 >> opr2;
	  }
	  break;
	case R_LARCH_SOP_ADD:
	  {
	    grub_uint64_t opr2=oprs[opri];
	    opri--;
	    grub_uint64_t opr1=oprs[opri];
	    opri--;
	    opri++;
	    oprs[opri]=opr1 + opr2;
	  }
	  break;
	case R_LARCH_SOP_AND:
	  {
	    grub_uint64_t opr2=oprs[opri];
	    opri--;
	    grub_uint64_t opr1=oprs[opri];
	    opri--;
	    opri++;
	    oprs[opri]=opr1 & opr2;
	  }
	  break;
	case R_LARCH_SOP_IF_ELSE:
	  {
	    grub_uint64_t opr3=oprs[opri];
	    opri--;
	    grub_uint64_t opr2=oprs[opri];
	    opri--;
	    grub_uint64_t opr1=oprs[opri];
	    opri--;
	    if(opr1)
	      {
	    	opri++;
	    	oprs[opri]=opr2;
	      }
	    else
	      {
	    	opri++;
	    	oprs[opri]=opr3;
	      }
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_10_5:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place=(*(grub_uint64_t *)place) | ((opr1 & 0x1f) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_U_10_12:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place=(*(grub_uint64_t *)place) | ((opr1 & 0xfff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_10_12:
	  {
	    if(la_abs==1)
	      la_abs=0;
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place= (*(grub_uint64_t *)place) | ((opr1 & 0xfff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_10_16:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place= (*(grub_uint64_t *)place) | ((opr1 & 0xffff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_10_16_S2:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place= (*(grub_uint64_t *)place) | (((opr1 >> 2) & 0xffff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_5_20:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place= (*(grub_uint64_t *)place) | ((opr1 & 0xfffff)<<5)	;
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_0_5_10_16_S2:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place=(*(grub_uint64_t *)place) | (((opr1 >> 2) & 0xffff) << 10);
	    *(grub_uint64_t *)place=(*(grub_uint64_t *)place) | ((opr1 >> 18) & 0x1f);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_0_10_10_16_S2:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)place=(*(grub_uint64_t *)place) | (((opr1 >> 2) & 0xffff) << 10);
	    *(grub_uint64_t *)place=(*(grub_uint64_t *)place) | ((opr1 >> 18) & 0x3ff);
	  }
	  break;
	default:
	  {
	    char rel_info[17]; /* log16(2^64) = 16, plus NUL. */

	    grub_snprintf (rel_info, sizeof (rel_info) - 1, "%" PRIxGRUB_UINT64_T,
			   (grub_uint64_t) ELF_R_TYPE (rel->r_info));
	    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			       N_("relocation 0x%s is not implemented yet"), rel_info);
	  }
	  break;
	}
    }
  return GRUB_ERR_NONE;
}

