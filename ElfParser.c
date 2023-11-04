#include "ElfParser.h"

void read_elf_header_64(int fd, Elf64_Ehdr *header) {

	long retval; 
	retval = (fd, 0, SEEK_SET);
	if(retval  == (__off_t)-1) 
		handle_error("(ElfParser.c: parse_elf_header_64) lseek failed.\n");
	
	retval = read(fd, (void *)(header), sizeof(Elf64_Ehdr));

	if(retval != sizeof(Elf64_Ehdr)) {
		printf("%ld\n", retval);
		handle_error("(ElfParser.c: parse_elf_header_64) header read failed.");
	}
}


int is_elf(unsigned char e_ident[]) {
	int result = 1;
	result &= (e_ident[EI_MAG0] == ELFMAG0);
	result &= (e_ident[EI_MAG1] == ELFMAG1);
	result &= (e_ident[EI_MAG2] == ELFMAG2);
	result &= (e_ident[EI_MAG3] == ELFMAG3);
	return result;
}


void load_pheaders_64(int fd, Elf64_Ehdr *header, Elf64_Phdr pheaders[]) {
	int retval;
	retval = lseek(fd, header->e_phoff, SEEK_SET);
	if(retval == (off_t)-1) 
		handle_error("(ElfParser.c: load_pheaders_64) lseek failed.\n");
	for(Elf64_Half i = 0; i < header->e_phnum; ++i) {
		retval = read(fd, &(pheaders[i]), header->e_phentsize);
		if(retval != header->e_phentsize) 
			handle_error("(ElfParser.c: load_pheaders_64) pheader read failed.\n");
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
				if(p_type > 7)
					handle_error("(ElfParser.c: print_program_headers): Bad p_type.\n");
				printf("%s\n", types[p_type]);
				break;
		}
	}
}

