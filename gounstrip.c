/*
 * Copyright 2020 Conrad Meyer
 */
#include <sys/types.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>
#include <libelftc.h>

#include "libelftc/libelftc.h"

static size_t shstrndx;

#define errelf(ecode, m, ...) \
	errx(ecode, m ": %s", ## __VA_ARGS__, elf_errmsg(-1))

static Elf_Scn *
elf_section_by_name(Elf *h, const char *nam)
{
	Elf_Scn *res;
	GElf_Shdr shdr;
	const char *snam;

	res = NULL;
	while ((res = elf_nextscn(h, res)) != NULL) {
		if (gelf_getshdr(res, &shdr) == NULL)
			errelf(1, "gelf_getshdr");
		snam = elf_strptr(h, shstrndx, shdr.sh_name);
		if (snam == NULL)
			errelf(1, "elf_strptr");
		if (strcmp(snam, nam) == 0)
			return (res);
	}
	return (NULL);
}

static uint64_t __unused
get_u64(uint8_t **iter)
{
	uint64_t r;
	memcpy(&r, *iter, sizeof(r));
	*iter += sizeof(r);
	return (r);
}

static uint32_t
get_u32(uint8_t **iter)
{
	uint32_t r;
	memcpy(&r, *iter, sizeof(r));
	*iter += sizeof(r);
	return (r);
}

static uint8_t
get_u8(uint8_t **iter)
{
	uint8_t r;
	r = **iter;
	*iter += sizeof(r);
	return (r);
}

static uint64_t
get_uptr(uint8_t **iter, unsigned addr_size)
{
	uint64_t u64;
	uint32_t u32;
	void *dst;

	if (addr_size == 8)
		dst = &u64;
	else if (addr_size == 4)
		dst = &u32;
	else
		abort();

	memcpy(dst, *iter, sizeof(u64));
	*iter += addr_size;

	if (addr_size == 8)
		return (u64);
	else if (addr_size == 4)
		return (u32);
	else
		abort();
}

#define allocate_shstrtab_entries(e, ...) \
	allocate_shstrtab_entries_(e, __VA_ARGS__, NULL)
static void
allocate_shstrtab_entries_(Elf *h, /* const char *nam, size_t *ndx_out, NULL */
    ...)
{
	Elf_Data *scndata;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	va_list ap;
	const char *name;
	size_t *ndx_out;
	char *data;
	size_t needed;

	scn = elf_section_by_name(h, ".shstrtab");
	if (scn == NULL)
		errx(1, "binary has no .shstrtab?");
	gelf_getshdr(scn, &shdr);

	/* Create contiguous shstrtab addendum and emit allocated offsets. */
	va_start(ap, h);
	needed = 0;
	data = NULL;
	while (true) {
		size_t entrysz;

		name = va_arg(ap, const char *);
		if (name == NULL)
			break;
		ndx_out = va_arg(ap, size_t *);
		*ndx_out = shdr.sh_size + needed;

		entrysz = strlen(name) + 1;
		data = realloc(data, needed + entrysz);
		memcpy(data + needed, name, entrysz);
		needed += entrysz;
	}
	va_end(ap);

	assert(needed > 0);

	scndata = elf_newdata(scn);
	scndata->d_buf = data;
	scndata->d_size = needed;
	/*
	 * _libelf_compute_section_extents will recompute sh_size from list of
	 * data buffers.
	 */
}

static Elf_Scn *
create_elf_section(Elf *h, GElf_Word sh_name, GElf_Word sh_type,
    GElf_Word sh_link)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;

	scn = elf_newscn(h);
	gelf_getshdr(scn, &shdr);
	shdr.sh_name = sh_name;
	shdr.sh_type = sh_type;
	shdr.sh_link = sh_link;
	gelf_update_shdr(scn, &shdr);

	return (scn);
}

static void
process_pclntab(Elf *elf, Elf_Data *pcdat, Elf_Scn *strscn, Elf_Scn *symscn)
{
	uint8_t *pcview, *iter;
	Elf64_Sym *new_symtab;
	size_t textndx;

	iter = pcview = pcdat->d_buf;

	uint32_t magic = get_u32(&iter);
	if (magic == 0xfffffffb)
		/* OK */ ;
	else if (magic == 0xfbffffff)
		errx(1, "cross-endian");
	else
		errx(1, "endian detection awry");

	iter += 2;
	uint8_t quantum, addr_size;

	quantum = get_u8(&iter);
	(void)quantum;
	addr_size = get_u8(&iter);

	/* Initialize strtab, symtab headers. */
	GElf_Shdr symshdr, strshdr;
	gelf_getshdr(strscn, &strshdr);
	strshdr.sh_addralign = 1;
	gelf_update_shdr(strscn, &strshdr);

	gelf_getshdr(symscn, &symshdr);
	symshdr.sh_addralign = addr_size;
	symshdr.sh_entsize = sizeof(*new_symtab);
	//symshdr.sh_info = 1; // no idea.
	gelf_update_shdr(symscn, &symshdr);

	Elf_Data *symdat, *strdat;
	symdat = elf_newdata(symscn);
	strdat = elf_newdata(strscn);

	uint64_t N;
	N = get_uptr(&iter, addr_size);

	Elftc_String_Table *new_strtab = elftc_string_table_create(0);
	new_symtab = calloc(N, sizeof(*new_symtab));

	textndx = elf_ndxscn(elf_section_by_name(elf, ".text"));

	for (uint64_t i = 0; i < N; i++) {
		uint64_t foff, namoff;
		uint32_t namaddr;

		foff = get_uptr(&iter, addr_size);
		namoff = get_uptr(&iter, addr_size);
		namaddr = *(uint32_t *)(pcview + namoff + addr_size);

		//printf("%016jx  %s\n", (uintmax_t)foff, &pcview[namaddr]);

		size_t ndx = elftc_string_table_insert(new_strtab,
		    (void *)&pcview[namaddr]);
		new_symtab[i] = (Elf64_Sym) {
			.st_name = ndx,
			.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC),
			.st_other = STV_DEFAULT,
			.st_shndx = textndx,
			.st_value = foff,
			/* TODO We may be able to compute a reasonable st_size. */
			.st_size = 0,
		};
	}

	size_t strsz;
	strdat->d_buf = (void *)elftc_string_table_image(new_strtab, &strsz);
	strdat->d_size = strsz;

	symdat->d_align = addr_size;
	symdat->d_buf = new_symtab;
	symdat->d_size = N * sizeof(*new_symtab);
	/*
	 * _libelf_compute_section_extents will recompute sh_size from list of
	 * data buffers.
	 */
}

int
main(int argc, char **argv)
{
	Elf *elf;
	int fd;

	if (argc != 2)
		errx(2, "Usage: gounstrip <binary>");

	fd = open(argv[1], O_RDWR, 0);
	if (fd < 0)
		err(1, "open: %s", argv[1]);

	(void)elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (elf == NULL)
		errelf(1, "elf_begin");
	if (elf_kind(elf) != ELF_K_ELF)
		errx(1, "%s: not an ELF file.", argv[1]);

	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		errelf(1, "getshstrndx");

	Elf_Scn *scn;
	scn = elf_section_by_name(elf, ".symtab");
	if (scn != NULL)
		errx(1, "binary already has .symtab");
	scn = elf_section_by_name(elf, ".strtab");
	if (scn != NULL)
		errx(1, "binary has .strtab but not .symtab???");

	// Allocate symtab and strtab; first we need strings for their section
	// names in shstrtab.
	size_t symtabshndx, strtabshndx;
	allocate_shstrtab_entries(elf, ".symtab", &symtabshndx, ".strtab",
	    &strtabshndx);
	Elf_Scn *strtab, *symtab;

	strtab = create_elf_section(elf, strtabshndx, SHT_STRTAB, 0);
	symtab = create_elf_section(elf, symtabshndx, SHT_SYMTAB,
	    elf_ndxscn(strtab));

	// Find and walk gopclntab to generate addr:symbol pairs
	scn = elf_section_by_name(elf, ".gopclntab");
	if (scn == NULL)
		errx(1, ".gopclntab not found");

	Elf_Data *pclndat = elf_rawdata(scn, NULL);
	process_pclntab(elf, pclndat, strtab, symtab);

	off_t rc = elf_update(elf, ELF_C_WRITE);
	if (rc < 0)
		errelf(1, "elf_update");
	elf_end(elf);
	return (0);
}
