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

#include "common.h"

#define NT_DUMPLIST 80
#define NT_OWNER "minicoredumper"
#define NT_NAME ".note.minicoredumper.dumplist"

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

static Elf_Scn *add_dump_section(Elf *e, Elf_Scn *strtab_scn)
{
	GElf_Shdr shdr;
	GElf_Word name;
	Elf_Scn *scn;

	if (append_strtab_name(strtab_scn, NT_NAME, &name) != 0)
		return NULL;

	scn = elf_newscn(e);
	if (!scn)
		return NULL;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return NULL;

	shdr.sh_name = name;
	shdr.sh_type = SHT_NOTE;
	shdr.sh_addralign = 4;

	gelf_update_shdr(scn, &shdr);

	return scn;
}

static int add_dump_data(Elf_Scn *scn, void *dump_data, GElf_Word size)
{
	GElf_Shdr shdr;
	Elf_Data *data;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	data = elf_newdata(scn);
	if (!data)
		return -1;

	data->d_align = 4;
	data->d_off = shdr.sh_size;
	data->d_buf = dump_data;
	data->d_type = ELF_T_NHDR;
	data->d_size = size;
	data->d_version = EV_CURRENT;

	shdr.sh_size += data->d_size;

	gelf_update_shdr(scn, &shdr);

	return 0;
}

static GElf_Word update_section_offset(Elf_Scn *scn, GElf_Off offset)
{
	GElf_Shdr shdr;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return -1;

	shdr.sh_offset = offset;

	gelf_update_shdr(scn, &shdr);

	return shdr.sh_size;
}

static GElf_Off get_last_offset(Elf *e, size_t strtab_ndx, int *has_sections,
				Elf_Scn **dumplist_scn)
{
	GElf_Off last_offset = 0;
	Elf_Scn *scn = NULL;
	GElf_Off offset;
	GElf_Shdr shdr;
	char *name;

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

		name = elf_strptr(e, strtab_ndx, shdr.sh_name);

		if (name && strcmp(name, NT_NAME) == 0) {
			/* overwrite existing dumplist
			 * (but get a handle first) */
			*dumplist_scn = scn;
			continue;
		} else if (elf_ndxscn(scn) == strtab_ndx) {
			/* overwrite existing shdrstr table */
			continue;
		} else {
			offset = shdr.sh_offset + shdr.sh_size;
		}

		if (offset > last_offset)
			last_offset = offset;
	};

	return last_offset;
}

static void *set_desc_item(int elfclass, void *desc, off64_t start,
			   off64_t len)
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

static void *get_desc_item(int elfclass, void *desc, off64_t *start,
			   off64_t *len)
{
	if (elfclass == ELFCLASS32) {
		uint32_t *ptr32 = desc;

		*start = *ptr32;
		ptr32++;
		*len = *ptr32;
		ptr32++;

		return ptr32;
	} else {
		uint64_t *ptr64 = desc;

		*start = *ptr64;
		ptr64++;
		*len = *ptr64;
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

#define NOTE_SZ_SPACE(sz) ((sz + 3) & ~3)
#define NOTE_NAME_PTR(n) (((void *)n) + sizeof(*n))
#define NOTE_DESC_PTR(n, sz) (((void *)NOTE_NAME_PTR(n)) + NOTE_SZ_SPACE(sz))

static int alloc_dump_note(struct core_data *dump_list, int elfclass,
			   void **note, size_t *size)
{
	struct core_data *cur;
	size_t note_size;
	size_t name_size;
	size_t desc_size;
	int count = 0;
	GElf_Nhdr *n;
	char *desc;

	for (cur = dump_list; cur; cur = cur->next) {
                if (cur->end == cur->start)
			continue;
		count++;
	}

	if (count == 0) {
		*note = NULL;
		*size = 0;
		return 0;
	}

	name_size = strlen(NT_OWNER) + 1;
	desc_size = get_desc_item_size(elfclass) * count;

	note_size = sizeof(*n) + NOTE_SZ_SPACE(name_size) +
		    NOTE_SZ_SPACE(desc_size);

	n = calloc(1, note_size);
	if (!n)
		return -1;

	n->n_type = NT_DUMPLIST;
	n->n_namesz = name_size;
	n->n_descsz = desc_size;
	sprintf(NOTE_NAME_PTR(n), NT_OWNER);

	desc = NOTE_DESC_PTR(n, name_size);
	for (cur = dump_list; cur; cur = cur->next) {
                if (cur->end == cur->start)
			continue;
		desc = set_desc_item(elfclass, desc, cur->mem_start,
				     cur->end - cur->start);
        }

	*size = note_size;
	*note = n;

	return 0;
}

static void _prune_dump_list(int elfclass, void *desc, int count,
			     struct core_data *dump_list)
{
	struct core_data *cur;
	off64_t start;
	off64_t end;
	off64_t len;
	int i;

	/* iterate through all dumps of note */

	for (i = 0; i < count; i++) {
		desc = get_desc_item(elfclass, desc, &start, &len);

		end = start + len;

		/* iterate through all _new_ dump */

		for (cur = dump_list; cur; cur = cur->next) {
			if (cur->end == cur->start)
				continue;
			if (cur->mem_start >= start &&
			    cur->mem_start + (cur->end - cur->start) <= end) {
				/* already covered, "disable" this dump */
				cur->end = cur->start;
				break;
			}
		}
	}
}

static int prune_dump_list(int elfclass, Elf_Data *data,
			   struct core_data *dump_list)
{
	char *name;
	GElf_Nhdr *n;
	size_t nsize;
	void *desc;
	int count;

	n = data->d_buf;

	/* iterate through all notes */

	while (n < (GElf_Nhdr *)(data->d_buf + data->d_size)) {
		name = NOTE_NAME_PTR(n);
		desc = NOTE_DESC_PTR(n, n->n_namesz);

		nsize = sizeof(*n) + NOTE_SZ_SPACE(n->n_namesz) +
			NOTE_SZ_SPACE(n->n_descsz);

		/* only process notes we recognize */
		if (strcmp(name, NT_OWNER) == 0 && n->n_type == NT_DUMPLIST) {
			count = n->n_descsz / get_desc_item_size(elfclass);

			_prune_dump_list(elfclass, desc, count, dump_list);
		}

		n = ((void *)n) + nsize;
	}

	return 0;
}

int add_dump_list(int core_fd, size_t *core_size,
		  struct core_data *dump_list, off64_t *dump_offset)
{
	Elf_Scn *dumplist_scn = NULL;
	GElf_Off last_offset;
	Elf_Scn *strtab_scn;
	size_t strtab_ndx;
	void *note = NULL;
	size_t note_size;
	int has_sections;
	size_t sec_size;
	GElf_Ehdr ehdr;
	Elf_Data *data;
	int err = -1;
	Elf *e;

	/*
	 * initial setup
	 */

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -1;

	lseek64(core_fd, 0, SEEK_CUR);

	e = elf_begin(core_fd, ELF_C_RDWR, NULL);
	if (!e)
		return -1;

	if (elf_kind(e) != ELF_K_ELF)
		goto out;

	elf_flagelf(e, ELF_C_SET, ELF_F_LAYOUT);

	/*
	 * get string index
	 */

	if (gelf_getehdr(e, &ehdr) == NULL)
		goto out;

	if (elf_getshdrstrndx(e, &strtab_ndx) != 0)
		goto out;

	/*
	 * load and check all sections
	 */

	last_offset = get_last_offset(e, strtab_ndx, &has_sections,
				      &dumplist_scn);
	if (last_offset == 0)
		last_offset = *core_size;

	if (dump_offset)
		*dump_offset = last_offset;

	/*
	 * create or read in strtab section
	 */

	if (strtab_ndx == 0) {
		strtab_scn = add_shstrtab_section(e);
		if (!strtab_scn)
			goto out;

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
				goto out;
			}
		}
	} else {
		strtab_scn = elf_getscn(e, strtab_ndx);
		if (!strtab_scn)
			goto out;

		/* read in existing data */
		data = NULL;
		do {
			data = elf_getdata(strtab_scn, data);
		} while (data);
	}

	/*
	 * create or read in dumplist section
	 */

	if (dumplist_scn) {
		/* read in existing data */
		data = NULL;
		while (1) {
			data = elf_getdata(dumplist_scn, data);
			if (!data)
				break;

			/* disable dump list items that are already
			 * covered by the existing data */
			if (prune_dump_list(gelf_getclass(e), data,
					    dump_list) != 0) {
				goto out;
			}
		}
	} else {
		/* create new section */
		dumplist_scn = add_dump_section(e, strtab_scn);
	}

	/*
	 * add dump list data
	 */

	if (alloc_dump_note(dump_list, gelf_getclass(e), &note,
			    &note_size) != 0) {
		goto out;
	}

	/* note may be NULL if there are no _new_ dump list items */
	if (note) {
		if (add_dump_data(dumplist_scn, note, note_size) != 0)
			goto out;
	}

	/*
	 * update dumplist and strtab offsets
	 */

	sec_size = update_section_offset(dumplist_scn, last_offset);
	if (sec_size == 0)
		goto out;
	last_offset += sec_size;

	sec_size = update_section_offset(strtab_scn, last_offset);
	if (sec_size == 0)
		goto out;
	last_offset += sec_size;

	/*
	 * flush, cleanup
	 */

	if (gelf_getehdr(e, &ehdr) == NULL)
		goto out;
	ehdr.e_shentsize = gelf_fsize(e, ELF_T_SHDR, 1, EV_CURRENT);
	ehdr.e_shstrndx = elf_ndxscn(strtab_scn);
	ehdr.e_shoff = last_offset;
	gelf_update_ehdr(e, &ehdr);

	elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);

	err = elf_update(e, ELF_C_WRITE);
	if (err < 0)
		goto out;

	/*
	 * set new core size
	 */

	if (gelf_getehdr(e, &ehdr) == NULL)
		goto out;

	*core_size = last_offset + (ehdr.e_shentsize * ehdr.e_shnum);

	err = 0;
out:
	elf_end(e);

	if (note)
		free(note);
	return err;
}
