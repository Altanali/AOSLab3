#include "ElfParser.h"



int main(int argc, char *argv[]) {
	if(argc != 2) handle_error("Usage: Require an executable to load.\n");

	int fd = open(argv[1], O_RDONLY);
	if((fd == -1))
		handle_error("(LazyLoader.c: main): Failed to open executable.\n");
	Elf64_Ehdr header;

	read_elf_header_64(fd, &header);
	if(!is_elf(header.e_ident)) {
		handle_error("(LazyLoader.c: main): Invalid ELF header.\n");
	}

	Elf64_Phdr pheaders[header.e_phnum];
	switch(header.e_type) {
		case ET_EXEC:
			printf("ELF Type Executable\n");
			load_pheaders_64(fd, &header, pheaders);
			break;
		case ET_DYN: 
			printf("ELF Type Dynamic\n");
			load_pheaders_64(fd, &header, pheaders);
			break;
		default:
			break;
	}
	
	print_program_headers(header.e_phnum, pheaders);

}