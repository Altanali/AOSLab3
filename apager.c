#define _GNU_SOURCE
#include "ElfParser.h"

int elf_fd = 0;
int envc = 0;
Elf64_Addr program_header_address = 0;
Elf64_Addr virt_program_entry = 0;
Elf64_Addr exec_stack_pointer = 0;
char *argv_strings, *envp_strings;
void *esp;

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
	while (auxv_null->a_type!= AT_NULL) {
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

int create_elf_tables(Elf64_Ehdr *header, char *envp[], int argc, void *esp) {
	int i;
	int num_aux_elements;
	while (*envp != NULL) envp++;
	envp++;
	Elf64_auxv_t *envpntr = (Elf64_auxv_t *)(envp);
	while(envpntr->a_type != AT_NULL) {
		++num_aux_elements;
		++envpntr;
	}
	Elf64_auxv_t aux_vector[num_aux_elements + 1];
	memset(aux_vector, 0, num_aux_elements*sizeof(Elf64_auxv_t));
	envpntr = ((Elf64_auxv_t *)(envp));
	for(i = 0, envpntr = ((Elf64_auxv_t *)(envp)); envpntr->a_type != AT_NULL; ++envpntr, ++i) {
		aux_vector[i] = *envpntr;
		if(envpntr->a_type == AT_ENTRY) 
			aux_vector[i].a_un.a_val = header->e_entry;
		if(envpntr->a_type == AT_PHNUM) 
			aux_vector[i].a_un.a_val = header->e_phnum;
		if(envpntr->a_type == AT_PHENT) 
			aux_vector[i].a_un.a_val = header->e_phentsize;
		if(envpntr->a_type == AT_PHDR) {
			aux_vector[i].a_un.a_val = program_header_address;
		}
	}
	num_aux_elements += 2;
	aux_vector[num_aux_elements].a_type = AT_NULL;
	aux_vector[num_aux_elements].a_un.a_val = 0;
	esp = (void *) ((uint64_t *)(esp) - 2*num_aux_elements);
	

	esp = (void *) ((uint64_t *)(esp) - ((argc + envc + 4)));
	esp = (void *)((uint64_t)(esp) & ~15UL);

	exec_stack_pointer = (Elf64_Addr)esp;
	assert(exec_stack_pointer % 8 == 0);

	/*esp is now at the "top" of the stack - but we haven't loaded anything yet,
	just allocated the space for it
	Growing the stack manually. 
	*/
	*(long *)esp = (long)argc;
	esp += sizeof(long);
	size_t arg_len;
	char *temp = argv_strings;
	for(int i = 0; i < argc; ++i) {
		*((char **)esp) = temp;
		esp += sizeof(char *);
		arg_len = strlen(temp);
		temp += arg_len + 1;
	}
	*(long *)esp = 0;
	esp += sizeof(long *);

	temp = envp_strings;
	for(int i = 0; i < envc - 1; ++i) {
		*((char **)esp) = temp;
		esp += sizeof(char *);
		arg_len = strlen(temp);
		temp += arg_len + 1;
	}
	*(long *)esp = 0;
	esp += sizeof(long *);

	memcpy(esp, aux_vector, sizeof(Elf64_auxv_t)*i);

	return 0;


}

int go_to_start() {
	asm("movq $0, %rax");
	asm("movq $0, %rbx");
	asm("movq $0, %rcx");
	asm("movq $0, %rdx");
	asm("movq %0, %%rsp" : : "r" (exec_stack_pointer));
	asm volatile("jmp *%0" : : "r" (virt_program_entry));
}

void setup_stack(int argc, char *argv[], char *envp[], Elf64_Ehdr *header){

	void *stack_low = mmap((void *)STACK_START, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_GROWSDOWN, 0, 0);
	if(stack_low == MAP_FAILED) 
		handle_error("(LazyLoader.c: setup_stack) stack mmap failed.\n");
	memset(stack_low, 0, STACK_SIZE);
	esp = (void *)(STACK_START + STACK_SIZE);

	/* push env to stack */
	char **envptr;
	size_t len;
	envc = 0;
	while(*envptr != NULL) {
		++envptr; ++envc;
	}
	for(int i = envc - 1; i >= 0; --i) {
		len = strlen(envp[i]);
		esp -= (len + 1);
		memcpy(esp, envp[i], len + 1);
	}

	//push argv onto the stack backwards
	for (int i = argc - 1; i >= 0; i--) {
		len = strlen(argv[i]);
		esp = ((char *)esp) - len - 1;
		strcpy((char *)esp, argv[i]);
	}
	argv_strings = esp;
	//Aligning to a factor of 8 by rounding down (adding padding to the stack)
	esp = (void *)arch_align_stack(esp);
	return;

}


void exec_elf64(char *elf, Elf64_Ehdr *header, int argc, char **argv, char **envp) {

	Elf64_Phdr pheaders[header->e_phnum];
	load_pheaders_64(elf, header, pheaders);
	if(header->e_phnum != 0)
		program_header_address = pheaders[0].p_vaddr + header->e_phoff;
	// print_program_headers(header->e_phnum, pheaders);
	uint64_t load_size = calculate_load_size(header->e_phnum, pheaders);

	//Actually load the segments into memory
	load_segments(elf, header->e_phnum,  pheaders, load_size);

	Elf64_Shdr sheaders[header->e_shnum];
	uint16_t str_table_dex = header->e_shstrndx;
	if(str_table_dex == SHN_XINDEX && header->e_shnum > 0) 
		str_table_dex = (uint16_t)(sheaders[0].sh_link);

	load_sheaders_64(elf, header, sheaders);
	// print_section_headers(header->e_shnum, sheaders);
	
	Elf64_Addr entry_point = header->e_entry;
	virt_program_entry = entry_point;

	//setup stack
	setup_stack(argc, argv, envp, header);
	create_elf_tables(header, envp, argc, esp);
	// stack_check((void *)exec_stack_pointer, argc, argv);



	go_to_start();
	
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
			exec_elf64(elf_memory, &header, argc - 1, &argv[1], envp);	
			break;
		case ET_DYN: 
			printf("ELF Type Dynamic\n");
			exec_elf64(elf_memory, &header, argc - 1, &argv[1], envp);
			break;
		default:
			break;
	}
	

}