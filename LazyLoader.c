#define _GNU_SOURCE
#include "ElfParser.h"

int elf_fd = 0;
Elf64_Addr program_header_address = 0;
Elf64_Addr virt_program_entry = 0;

void stack_check(void* top_of_stack, uint64_t argc, char** argv) {
	printf("----- stack check -----\n");

	assert(((uint64_t)top_of_stack) % 8 == 0);
	printf("top of stack is 8-byte aligned\n");

	uint64_t* stack = top_of_stack;
	uint64_t actual_argc = *(stack++);
	printf("argc: %lu\n", actual_argc);
	assert(actual_argc == argc);

	for (int i = 0; i < argc; i++) {
		char* argp = (char*)*(stack++);
		assert(strcmp(argp, argv[i]) == 0);
		printf("arg %d: %s\n", i, argp);
	}


	// Argument list ends with null pointer
	assert(*(stack++) == 0);

	int envp_count = 0;
	while (*(stack++) != 0)
		envp_count++;

	printf("env count: %d\n", envp_count);

	Elf64_auxv_t* auxv_start = (Elf64_auxv_t*)stack;
	Elf64_auxv_t* auxv_null = auxv_start;
	while (auxv_null->a_type != AT_NULL) {
		auxv_null++;
	}
	printf("aux count: %lu\n", auxv_null - auxv_start);
	printf("----- end stack check -----\n");
}

//Adds the type/value pair, and updates the stack pointer
void new_aux_ent(uint64_t **espp, uint64_t a_type, uint64_t value) {
	*(--(*espp)) = a_type;
	*(--(*espp)) = value;
}

void *setup_stack(int argc, char *argv[], char *envp[], Elf64_Ehdr *header){
	size_t stack_size = STACK_SIZE_PAGES*getpagesize();
	void *stack_low = mmap(NULL, stack_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	void *esp = stack_low + stack_size;
	void **espp = &esp;
	//Pad till esp % 8 == 0
	esp -= ((uint64_t)esp % 8);

	//Create aux vector 
	
	new_aux_ent((uint64_t **)espp, 0, AT_NULL); //End of vector
	new_aux_ent((uint64_t **)espp, elf_fd, AT_EXECFD); 
	new_aux_ent((uint64_t **)espp, virt_program_entry, AT_ENTRY);
	new_aux_ent((uint64_t **)espp, 0, AT_NOTELF);
	new_aux_ent((uint64_t **)espp, virt_program_entry, AT_PHDR);
	new_aux_ent((uint64_t **)espp, getpagesize(), AT_PAGESZ);
	new_aux_ent((uint64_t **)espp, header->e_phnum, AT_PHNUM);
	new_aux_ent((uint64_t **)espp, header->e_phentsize, AT_PHENT);
	new_aux_ent((uint64_t **)espp, program_header_address, AT_PHDR);
	new_aux_ent((uint64_t **)espp, 0, AT_BASE);
	new_aux_ent((uint64_t **)espp, geteuid(), AT_EGID);
	new_aux_ent((uint64_t **)espp, getuid(), AT_UID);
	new_aux_ent((uint64_t **)espp, getpagesize(), AT_PAGESZ);









	//Add envp to the stack
	int envp_count = 0;
	Elf64_auxv_t *auxv;
	for ( auxv = (Elf64_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++) {
		printf("auxv_type: %lx\n", auxv->a_type);
	}
	for(char **curr_env = envp; *curr_env != NULL; ++curr_env) envp_count++;
	for(int i = envp_count; i >= 0; --i) {
		esp -= sizeof(char *);
		*((char **)esp) = envp[i];
		if(((uint64_t)esp % 8 != 0)) {
		}
	}
	
	//Load argv into the stack: 
	for(int i = argc; i >= 0; --i) {
		esp -= sizeof(char *);
		*((char **)esp) = argv[i];
		if(((uint64_t)esp % 8 != 0)) {
		}
	}
	*((uint64_t *)(esp) - 1) = argc;
	esp -= sizeof(uint64_t);
	stack_check(esp, argc, argv);
	return esp;

}
void exec_elf64(char *elf, Elf64_Ehdr *header, int argc, char **argv, char **envp) {

	Elf64_Phdr pheaders[header->e_phnum];
	load_pheaders_64(elf, header, pheaders);
	if(header->e_phnum != 0)
		program_header_address = pheaders[0].p_vaddr + header->e_phoff;
	// print_program_headers(header->e_phnum, pheaders);
	uint64_t load_size = calculate_load_size(header->e_phnum, pheaders);
	char *memory = mmap(NULL, load_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	memset(memory, 0x0, load_size);
	//Actually load the segments into memory
	load_segments(elf, header->e_phnum,  pheaders, memory, load_size);

	Elf64_Shdr sheaders[header->e_shnum];
	uint16_t str_table_dex = header->e_shstrndx;
	if(str_table_dex == SHN_XINDEX && header->e_shnum > 0) 
		str_table_dex = (uint16_t)(sheaders[0].sh_link);

	load_sheaders_64(elf, header, sheaders);
	// print_section_headers(header->e_shnum, sheaders);
	
	Elf64_Addr entry_point = header->e_entry + (Elf64_Addr)(memory);
	assert(entry_point < (Elf64_Addr)(memory) + load_size);
	virt_program_entry = entry_point;

	//setup stack
	void *esp = setup_stack(argc, argv, envp, header);
	

	uint64_t rsp_value = (uint64_t)(esp);

	asm("movq $0, %rax");
	asm("movq $0, %rbx");
	asm("movq $0, %rcx");
	asm("movq $0, %rdx");
	asm("movq %0, %%rsp" : : "r" (rsp_value));
	asm("jmp *%0" : : "c" (header->e_entry));
}


int main(int argc, char *argv[], char *envp[]) {
	if(argc < 2) handle_error("Usage: Require an executable to load.\n");

	int fd = open(argv[1], O_RDONLY);
	if((fd == -1))
		handle_error("(LazyLoader.c: main): Failed to open executable.\n");

	elf_fd = fd;
	char *elf_memory = load_elf_file(fd);
	Elf64_Ehdr header;

	read_elf_header_64(elf_memory, &header);
	if(!is_elf(header.e_ident)) {
		handle_error("(LazyLoader.c: main): Invalid ELF header.\n");
	}

	Elf64_Phdr pheaders[header.e_phnum];
	switch(header.e_type) {
		case ET_EXEC:
			printf("ELF Type Executable\n");
			exec_elf64(elf_memory, &header, argc, argv, envp);	
			break;
		case ET_DYN: 
			printf("ELF Type Dynamic\n");
			exec_elf64(elf_memory, &header, argc - 1, &argv[1], envp);
			break;
		default:
			break;
	}
	

}