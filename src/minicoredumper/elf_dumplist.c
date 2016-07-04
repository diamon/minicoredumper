/*
 * Copyright (c) 2016 Ericsson AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/types.h>
#include "corestripper.h"

#define NT_DUMPLIST 80

struct dumplist_note {
	GElf_Nhdr nhdr;
	char name[16];
	char desc[];
};

static struct dumplist_note note_template = {
	.nhdr = {
		.n_namesz = 15,
		.n_type = NT_DUMPLIST,
	},
	.name = { 'm', 'i', 'n', 'i', 'c', 'o', 'r', 'e',
		  'd', 'u', 'm', 'p', 'e', 'r', 0 },
};

static int append_strtab_name(Elf_Scn *strtab_scn, char *name_str,
			      GElf_Word *name)
{
	GElf_Shdr shdr;
	Elf_Data *data;

	if (gelf_getshdr(strtab_scn, &shdr) == NULL)
		return -1;

	data = elf_newdata(strtab_scn);
	if (!data)
		return -1;

	data->d_align = 1;
	data->d_off = shdr.sh_size;
	data->d_buf = name_str;
	data->d_type = ELF_T_BYTE;
	data->d_size = strlen(name_str) + 1;
	data->d_version = EV_CURRENT;

	*name = shdr.sh_size;

	shdr.sh_size += data->d_size;

	gelf_update_shdr(strtab_scn, &shdr);

	return 0;
}

static Elf_Scn *add_shstrtab_section(Elf *e)
{
	GElf_Word name;
	GElf_Shdr shdr;
	Elf_Scn *scn;

	scn = elf_newscn(e);
	if (!scn)
		return NULL;

	if (append_strtab_name(scn, "", &name) != 0)
		return NULL;

	if (append_strtab_name(scn, ".shstrtab", &name) != 0)
		return NULL;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return NULL;

	shdr.sh_name = name;
	shdr.sh_type = SHT_STRTAB;
	shdr.sh_flags = SHF_STRINGS;
	shdr.sh_addralign = 1;

	gelf_update_shdr(scn, &shdr);

	return scn;
}

static int add_debug_section(Elf *e, Elf_Scn *strtab_scn, GElf_Off offset,
			     GElf_Word size)
{
	GElf_Shdr shdr;
	GElf_Word name;
	Elf_Scn *scn;

	if (append_strtab_name(strtab_scn, ".debug", &name) != 0)
		return -1;

	scn = elf_newscn(e);
	if (!scn)
		return -1;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	shdr.sh_name = name;
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_offset = offset;
	shdr.sh_size = size;
	shdr.sh_addralign = 1;

	gelf_update_shdr(scn, &shdr);

	return 0;
}

static int add_dump_section(Elf *e, Elf_Scn *strtab_scn, GElf_Off offset,
			    void *raw_data, GElf_Word size)
{
	GElf_Shdr shdr;
	GElf_Word name;
	Elf_Data *data;
	Elf_Scn *scn;

	if (append_strtab_name(strtab_scn, ".note.minicoredumper.dumplist",
			       &name) != 0) {
		return -1;
	}

	scn = elf_newscn(e);
	if (!scn)
		return -1;

	data = elf_newdata(scn);
	if (!data)
		return -1;

	data->d_align = 4;
	data->d_buf = raw_data;
	data->d_type = ELF_T_NHDR;
	data->d_size = size;
	data->d_version = EV_CURRENT;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	shdr.sh_name = name;
	shdr.sh_type = SHT_NOTE;
	shdr.sh_size = size;
	shdr.sh_offset = offset;
	shdr.sh_addralign = 4;

	gelf_update_shdr(scn, &shdr);

	return 0;
}

static GElf_Off get_last_offset(Elf *e, int fd, size_t strtab_ndx,
				int *has_sections)
{
	GElf_Off last_offset = 0;
	Elf_Scn *scn = NULL;
	GElf_Off offset;
	GElf_Shdr shdr;

	*has_sections = 0;

	while (1) {
		scn = elf_nextscn(e, scn);
		if (!scn)
			break;

		if (gelf_getshdr(scn, &shdr) == NULL)
			return 0;

		*has_sections = 1;

		if (shdr.sh_type == SHT_NOBITS)
			continue;

		/* not interested in shdrstr table */
		if (elf_ndxscn(scn) == strtab_ndx)
			offset = shdr.sh_offset;
		else
			offset = shdr.sh_offset + shdr.sh_size;

		if (offset > last_offset)
			last_offset = offset;
	};

	return last_offset;
}

static int do_add_dump_list(struct dump_info *di, struct dumplist_note *note,
			    size_t size)
{
	GElf_Off store_offset;
	GElf_Off last_offset;
	Elf_Scn *strtab_scn;
	size_t strtab_ndx;
	int has_sections;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	int ret;
	Elf *e;
	int fd;

	/* INITIAL SETUP */

	lseek64(di->core_fd, 0, SEEK_CUR);

	e = elf_begin(di->core_fd, ELF_C_RDWR, NULL);
	if (!e)
		return -1;

	elf_flagelf(e, ELF_C_SET, ELF_F_LAYOUT);

	/* GET STRING INDEX */

	if (gelf_getehdr(e, &ehdr) == NULL)
		return -1;

	if (elf_getshdrstrndx(e, &strtab_ndx) != 0)
		return -1;

	/* LOAD AND CHECK ALL SECTIONS */

	last_offset = get_last_offset(e, fd, strtab_ndx, &has_sections);
	if (last_offset == 0)
		last_offset = di->core_file_size;

	store_offset = last_offset;

	/* READ IN OR CREATE SHSTRTAB SECTION */

	if (strtab_ndx == 0) {
		strtab_scn = add_shstrtab_section(e);
		if (!strtab_scn)
			return -1;

		ehdr.e_shstrndx = elf_ndxscn(strtab_scn);
		strtab_ndx = ehdr.e_shstrndx;

		if (!has_sections) {
			GElf_Off offset = ehdr.e_ehsize;

			/* cover everything after the elf header to ensure
			 * that there are no gaps for libelf to fill (the
			 * program headers are excluded also if they fall
			 * directly after the elf header) */

			if (offset == ehdr.e_phoff)
				offset += ehdr.e_phentsize * ehdr.e_phnum;

			if (add_debug_section(e, strtab_scn, offset,
					      last_offset - offset) != 0) {
				return -1;
			}
		}
	} else {
		Elf_Data *d = NULL;

		strtab_scn = elf_getscn(e, strtab_ndx);
		if (!strtab_scn)
			return -1;

		/* read in strtab data */
		do {
			d = elf_getdata(strtab_scn, d);
		} while (d);
	}

	/* ADD DUMP SECTION */

	if (add_dump_section(e, strtab_scn, last_offset, note, size) != 0)
		return -1;
	last_offset += size;

	/* UPDATE STRING TABLE SHDR */

	if (gelf_getshdr(strtab_scn, &shdr) == NULL)
		return -1;
	shdr.sh_offset = last_offset;
	gelf_update_shdr(strtab_scn, &shdr);

	last_offset += shdr.sh_size;

	/* FLUSH, CLEANUP */

	if (gelf_getehdr(e, &ehdr) == NULL)
		return -1;
	ehdr.e_shentsize = gelf_fsize(e, ELF_T_SHDR, 1, EV_CURRENT);
	ehdr.e_shstrndx = elf_ndxscn(strtab_scn);
	ehdr.e_shoff = last_offset;
	gelf_update_ehdr(e, &ehdr);

	last_offset += ehdr.e_shentsize * ehdr.e_shnum;

	elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);

	ret = elf_update(e, ELF_C_WRITE);
	if (ret < 0)
		return -1;

	elf_end(e);

	/* ADD NEW SECTIONS (AND HEADERS) TO CORE FILE */

	di->core_file_size = last_offset;

	add_core_data(di, store_offset, last_offset - store_offset,
		      di->core_fd, store_offset);

	return 0;
}

static void *set_desc(int elfclass, void *desc, off64_t start, off64_t len)
{
	if (elfclass == ELFCLASS32) {
		uint32_t *ptr32 = desc;

		*ptr32 = (uint32_t)start;
		ptr32++;
		*ptr32 = (uint32_t)len;
		ptr32++;

		return ptr32;
	} else {
		uint64_t *ptr64 = desc;

		*ptr64 = start;
		ptr64++;
		*ptr64 = len;
		ptr64++;

		return ptr64;
	}
}

static size_t get_desc_item_size(int elfclass)
{
	if (elfclass == ELFCLASS32)
		return (sizeof(uint32_t) * 2);
	else
		return (sizeof(uint64_t) * 2);
}

int add_dump_list(struct dump_info *di)
{
	struct dumplist_note *note;
	struct core_data *cur;
	size_t note_size;
	int count = 0;
	char *desc;
	int ret;

	for (cur = di->core_file; cur; cur = cur->next) {
                if (cur->end == cur->start)
			continue;
		count++;
	}

	note_size = sizeof(struct dumplist_note) +
		    (get_desc_item_size(di->elfclass) * count);

	note = malloc(note_size);
	if (!note)
		return -1;

	memcpy(note, &note_template, sizeof(note_template));

	desc = &note->desc[0];
	for (cur = di->core_file; cur; cur = cur->next) {
                if (cur->end == cur->start)
			continue;
		desc = set_desc(di->elfclass, desc, cur->mem_start,
				cur->end - cur->start);
        }

	note->nhdr.n_descsz = get_desc_item_size(di->elfclass) * count;

	ret = do_add_dump_list(di, note, note_size);

	free(note);

	return ret;
}
