#define _GNU_SOURCE
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

void load_segments(char *elf, Elf64_Half phnum, Elf64_Phdr pheaders[]) {
	Elf64_Half i;
	Elf64_Off offs;
	Elf64_Phdr *ppntr;
	Elf64_Addr addr;
	char *curr;
	int prot, prot_temp;
	prot_temp = PROT_READ | PROT_WRITE;
	for(i = 0, ppntr = pheaders; i < phnum; ++i, ++ppntr) {

		if(ppntr->p_type != PT_LOAD || ppntr->p_memsz == 0) continue;
		prot = 0;
		curr = elf + ppntr->p_offset;

		size_t align = ppntr->p_vaddr % sysconf(_SC_PAGE_SIZE);
		size_t v_addr = ppntr->p_vaddr - align;
		size_t ofs = ppntr->p_offset - align; //compensate for additional padding at beginning of page
		void *end;
		//Map the entire segment to the memory address given by ppnt->vaddr
		void *temp = (char*) mmap((void*) v_addr, align + ppntr->p_memsz, prot_temp, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if(temp == MAP_FAILED)
				handle_error("(ElfParser.c: load_segments) segment mmap failed");
		//copy file at ppntr->offs to ppntr->offs + ppntr->p_filesz TO ppntr->v_addr
		memmove((void *)ppntr->p_vaddr, elf + ppntr->p_offset, ppntr->p_filesz);
		if((ppntr->p_flags & PF_R)) 
			prot |= PROT_READ;
		if((ppntr->p_flags & PF_W)) 
			prot |= PROT_WRITE;
		if(ppntr->p_flags & PF_X) 
			prot |= PROT_EXEC;
		mprotect(temp, align + ppntr->p_memsz, prot);
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



int check_overlap(char **envp, Elf64_Addr other_entry) {
	char **envpp = envp;
	Elf64_auxv_t *aux;
	Elf64_Addr my_entry = 0;

	while(*envpp != NULL) envpp++;
	envpp++;
	for (aux = (Elf64_auxv_t *) envpp; aux->a_type != AT_NULL; aux++) {
		if (aux->a_type == AT_ENTRY) {
			my_entry = aux->a_un.a_val;	
		}
	}
	return my_entry == other_entry;

}