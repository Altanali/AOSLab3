#include "ElfParser.h"

void read_elf_header_64(char *elf, Elf64_Ehdr *header) {
	memmove(header, elf, sizeof(Elf64_Ehdr));
}


int is_elf(unsigned char e_ident[]) {
	int result = 1;
	result &= (e_ident[EI_MAG0] == ELFMAG0);
	result &= (e_ident[EI_MAG1] == ELFMAG1);
	result &= (e_ident[EI_MAG2] == ELFMAG2);
	result &= (e_ident[EI_MAG3] == ELFMAG3);
	return result;
}


void load_pheaders_64(char *elf, Elf64_Ehdr *header, Elf64_Phdr pheaders[]) {
	char *curr = elf + header->e_phoff;
	for(Elf64_Half i = 0; i < header->e_phnum; ++i) {
		memmove(&(pheaders[i]), curr, header->e_phentsize);
		curr += header->e_phentsize;
	}

}


void print_program_headers(Elf64_Half phnum, Elf64_Phdr pheaders[]) {
	char *types[] = {
		"PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE", "PT_SHLIB", "PT_PHDR", 
		"PT_LOPROC"
	};
	Elf64_Word p_type;
	for(Elf64_Half i = 0; i < phnum; ++i) {
		p_type = pheaders[i].p_type;
		if (p_type >= PT_LOPROC && p_type <= PT_HIPROC) {
			printf("RESERVED TYPE\n");
			continue;
		}


		switch(p_type) {
			case PT_GNU_PROPERTY:
				printf("PT_GNU_PROPERTY\n");
				break;
			case PT_GNU_RELRO:
				printf("PT_GNU_RELRO\n");
				break;
			case PT_GNU_STACK:
				printf("PT_GNU_STACK\n");
				break;
			case PT_GNU_EH_FRAME:
				printf("PT_GNU_EH_FRAME\n");
				break;
			default: 
				if(p_type > sizeof(types))
					handle_error("(ElfParser.c: print_program_headers): Bad p_type.\n");
				printf("%s\n", types[p_type]);
				break;
		}
	}
}

uint64_t calculate_load_size(Elf64_Half phnum, Elf64_Phdr pheaders[]) {
	uint64_t result = 0;
	Elf64_Half i;
	Elf64_Phdr *ppntr;
	for(i = 0, ppntr = pheaders; i < phnum; ++i, ++ppntr) {
		if(ppntr->p_type != PT_LOAD) continue;
		result = max(result, ppntr->p_vaddr + ppntr->p_memsz);
	}
	return result;
}

void load_segments(char *elf, Elf64_Half phnum, Elf64_Phdr pheaders[], char *memory, size_t load_size) {
	Elf64_Half i;
	Elf64_Off offs;
	Elf64_Phdr *ppntr;
	Elf64_Addr addr;
	Elf64_Addr start_address = (Elf64_Addr)(memory);
	Elf64_Addr end_address = (Elf64_Addr)(memory) + load_size;
	char *curr;
	int prot;
	printf("Start address: %p\nEnd address: %p\n", (char *)(start_address), (char *)(end_address));
	for(i = 0, ppntr = pheaders; i < phnum; ++i, ++ppntr) {
		if(ppntr->p_type != PT_LOAD || ppntr->p_memsz == 0) continue;
		curr = elf + ppntr->p_offset;
		addr = ppntr->p_vaddr + start_address;
		if((addr + ppntr->p_memsz) > end_address) 
			handle_error("(ElfParser.c: load_segments) segment exceeds memory boundary.\n");
		memmove((char *)(addr), curr, ppntr->p_filesz);
		
		if((ppntr->p_flags & PF_R)) {
			prot |= PROT_READ;
		}
		if((ppntr->p_flags & PF_W)) {
			prot |= PROT_WRITE;
		}
		if(ppntr->p_flags & PF_X) {
			prot |= PROT_EXEC;
		}

		mprotect((void *)(addr), ppntr->p_memsz, prot);
	}
}


void load_sheaders_64(char *elf, Elf64_Ehdr *header, Elf64_Shdr sheaders[]) {
	char *curr = elf + header->e_shoff;
	
	for(Elf64_Half i = 0; i < header->e_shnum; ++i) {
		memmove(&(sheaders[i]), curr, header->e_shentsize);
		curr += header->e_shentsize;
	}
}


//Prints the types of the headers 
void print_section_headers(Elf64_Half shnum, Elf64_Shdr sheaders[]) {
	Elf64_Half i;
	Elf64_Shdr *shptr;
	Elf64_Word sh_type;
	char *name;
	char *types[] = {
		"SHT_NULL", "SHT_PROGBITS", "SHT_SYMTAB", "SHT_STRTAB", 
		"SHT_RELA", "SHT_HASH", "SHT_DYNAMIC", "SHT_NOTE",
		"SHT_NOBITS", "SHT_REL", "SHT_SHLIB", "SHT_DYNSYM",
		"", "", "SHT_INIT_ARRAY", "SHT_FINI_ARAY", 
		"SHT_PREINIT_ARRAY", "SHT_GROUP", "SHT_SYMTAB_SHNDX"
	};
	for(i = 0, shptr = sheaders; i < shnum; ++i, ++shptr) {
		// name = sheaders[str_table_dex];
		sh_type = shptr->sh_type;
		if ((sh_type >= SHT_LOPROC && sh_type <= SHT_HIPROC) ||
			(sh_type >= SHT_LOOS && sh_type <= SHT_HIOS)) {
			printf("RESERVED TYPE\n");
			continue;
		}

		switch(sh_type) {
			case SHT_LOUSER:
				printf("SHT_LOUSER\n");
				break;
			case SHT_HIUSER:
				printf("SHT_HIUSER\n");
				break;
			default: 
				if(sh_type > sizeof(types)) {
					printf("type unknown: %xu\n", sh_type);
					handle_error("(ElfParser.c: print_program_headers) bad sh_type.\n");
				}
				printf("%s\n", types[sh_type]);
				break;
		}
	
	}
}

char *load_elf_file(int fd) {
	int retval;
	char *result; 
	retval = lseek(fd, 0, SEEK_SET);
	if(retval == (off_t)-1) 
		handle_error("(ElfParser.c: load_elf_file) failed to seek.\n");
	struct stat stat_obj;
	fstat(fd, &stat_obj);
	size_t file_size = stat_obj.st_size;
	result = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(result == MAP_FAILED) 
		handle_error("(ElfParser.c: load_elf_file) mmap of ELF file failed");
	return result;
}

