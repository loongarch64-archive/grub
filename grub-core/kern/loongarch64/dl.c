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
      || e->e_ident[EI_DATA] != ELFDATA2LSB
      || e->e_machine != EM_LOONGARCH64)
    return grub_error (GRUB_ERR_BAD_OS, N_("invalid arch-dependent ELF magic"));

  return GRUB_ERR_NONE;
}

#pragma GCC diagnostic ignored "-Wcast-align"

grub_err_t
grub_arch_dl_get_tramp_got_size (const void *ehdr __attribute__ ((unused)),
				 grub_size_t *tramp, grub_size_t *got)
{
  *tramp = 0;
  *got = 0;
  return GRUB_ERR_NONE;
}

/* Relocate symbols.  */
grub_err_t
grub_arch_dl_relocate_symbols (grub_dl_t mod, void *ehdr,
			       Elf_Shdr *s, grub_dl_segment_t seg)
{
  Elf_Ehdr *e = ehdr;
  Elf_Rel *rel, *max;
  grub_uint64_t oprs[RELOC_STACK_MAX]={0};
  int opri=-1;
  grub_uint32_t la_abs = 0;

  for (rel = (Elf_Rel *) ((char *) e + s->sh_offset),
	 max = (Elf_Rel *) ((char *) rel + s->sh_size);
       rel < max;
       rel = (Elf_Rel *) ((char *) rel + s->sh_entsize))
    {
      grub_uint8_t *addr;
      Elf_Sym *sym;
      Elf_Addr r_info;
      grub_uint64_t sym_value;

      if (seg->size < rel->r_offset)
	return grub_error (GRUB_ERR_BAD_MODULE,
			   "reloc offset is out of the segment");

      r_info = (grub_uint64_t) (rel->r_info);
      addr = (grub_uint8_t *) ((char*)seg->addr + rel->r_offset);
      sym = (Elf_Sym *) ((char*)mod->symtab
			 + mod->symsize * ELF_R_SYM (r_info));
      sym_value = sym->st_value;
      if (s->sh_type == SHT_RELA)
	{
	  sym_value += ((Elf_Rela *) rel)->r_addend;
	}
      switch (ELF_R_TYPE (r_info))
	{
	case R_LARCH_64:
	  {
	    *(grub_uint64_t *)addr=(grub_uint64_t)sym_value;
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
	    oprs[opri]=(grub_uint64_t)(sym_value-(grub_uint64_t)addr);
	  }
	break;
	case R_LARCH_SOP_PUSH_ABSOLUTE:
	  {
	    opri++;
	    oprs[opri]=(grub_uint64_t)sym_value;
	  }
	break;
	case R_LARCH_SOP_PUSH_PLT_PCREL:
	  {
	    opri++;
	    oprs[opri]=(grub_uint64_t)(sym_value-(grub_uint64_t)addr);
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
	    *(grub_uint64_t *)addr=(*(grub_uint64_t *)addr) | ((opr1 & 0x1f) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_U_10_12:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)addr=(*(grub_uint64_t *)addr) | ((opr1 & 0xfff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_10_12:
	  {
	    if(la_abs==1)
	      la_abs=0;
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)addr= (*(grub_uint64_t *)addr) | ((opr1 & 0xfff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_10_16:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)addr= (*(grub_uint64_t *)addr) | ((opr1 & 0xffff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_10_16_S2:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)addr= (*(grub_uint64_t *)addr) | (((opr1 >> 2) & 0xffff) << 10);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_5_20:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)addr= (*(grub_uint64_t *)addr) | ((opr1 & 0xfffff)<<5)	;
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_0_5_10_16_S2:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)addr=(*(grub_uint64_t *)addr) | (((opr1 >> 2) & 0xffff) << 10);
	    *(grub_uint64_t *)addr=(*(grub_uint64_t *)addr) | ((opr1 >> 18) & 0x1f);
	  }
	  break;
	case R_LARCH_SOP_POP_32_S_0_10_10_16_S2:
	  {
	    grub_uint64_t opr1 = oprs[opri];
	    opri--;
	    *(grub_uint64_t *)addr=(*(grub_uint64_t *)addr) | (((opr1 >> 2) & 0xffff) << 10);
	    *(grub_uint64_t *)addr=(*(grub_uint64_t *)addr) | ((opr1 >> 18) & 0x3ff);
	  }
	  break;
	default:
	  {
	    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			       N_("relocation 0x%x is not implemented yet"),
			       ELF_R_TYPE (r_info));
	  }
	  break;
	}
    }
  return GRUB_ERR_NONE;
}

