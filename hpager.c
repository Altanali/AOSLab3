#define _GNU_SOURCE
#include "ElfParser.h"
#include <signal.h>
#include <fcntl.h>
#ifndef PAGES_PER_FAULT
#define PAGES_PER_FAULT 2
#endif
int elf_fd = 0;
FILE *segfault_out = NULL;
int envc = 0;
int num_strings = 0;
Elf64_Addr program_header_address = 0;
Elf64_Phdr *pheaders = NULL;
Elf64_Ehdr *elf_header = NULL;
Elf64_Addr virt_program_entry = 0;
Elf64_Addr exec_stack_pointer = 0;
Elf64_Addr bss_low = 0;
Elf64_Addr bss_high = 0;
char *argv_strings, *envp_strings, *elf_memory, **string_table, *section_name_data;
void *esp;

void setup_handlers(struct sigaction *action);
void print_string_table();

void *map_page_from_vaddr(Elf64_Addr v_addr, Elf64_Phdr *ph) {
	assert(ph->p_vaddr <= v_addr && v_addr <= (ph->p_vaddr + ph->p_memsz));

	int prot = 0;
	if((ph->p_flags & PF_R)) 
			prot |= PROT_READ;
	if((ph->p_flags & PF_W)) 
		prot |= PROT_WRITE;
	if(ph->p_flags & PF_X) 
		prot |= PROT_EXEC;

	Elf64_Addr page_start = ELF_PAGESTART(v_addr);
	//retreive the target page
	void *page = mmap((void *)page_start, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if(page == MAP_FAILED) 
		handle_error("(hpager.c: map_page_from_vaddr): Failed to mmap a page.\n");
	memset(page, 0, PAGE_SIZE);

	//check that if nothing to copy: 
	if(page_start >= ph->p_vaddr + ph->p_filesz) {
		printf("mmap (vaddr: %p, offset: 0, size: %lu)\n", (void *)page_start, (size_t)PAGE_SIZE);
		return page;
	}
	//copy content files (if any) from v_addr in the original ELF file: 
	
	
	//offset this value by the actual offset into the file
	Elf64_Addr segment_start = max(page_start, ph->p_vaddr);
	Elf64_Addr segment_end = min(page_start + PAGE_SIZE, ph->p_vaddr + ph->p_filesz);
	size_t copy_size = segment_end - segment_start;

	//offset this value by the actual offset into the file
	uint64_t offs = ph->p_offset + (segment_start - ph->p_vaddr);
	memmove((void *)segment_start, elf_memory + offs, copy_size);
	printf("mmap (vaddr: %p, offset: %zu, size: %lu)\n", (void *)segment_start, offs,  (size_t)PAGE_SIZE);
	mprotect(page, PAGE_SIZE, prot);
	return page;
	
}


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
	int num_aux_elements = 0;
	while (*envp != NULL) envp++;
	envp++;
	Elf64_auxv_t *envpntr = (Elf64_auxv_t *)(envp);
	while(envpntr->a_type != AT_NULL) {
		++num_aux_elements;
		++envpntr;
	}
	++num_aux_elements; //for the AT_NULL element
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
		handle_error("(hpager.c: setup_stack) stack mmap failed.\n");
	else
		printf("mmap (vaddr: %p, offset: %zu, size: %lu)\n", (void *)STACK_START, (size_t)0, STACK_SIZE);
	memset(stack_low, 0, STACK_SIZE);
	esp = (void *)(STACK_START + STACK_SIZE);

	/* push env to stack */
	char **envptr = envp;
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
	envp_strings = esp;

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

void hpager_load_segments(char *elf, int phnum, Elf64_Phdr pheaders[]) {
	Elf64_Half i;
	Elf64_Off offs;
	Elf64_Phdr *ppntr;
	Elf64_Addr addr;
	
	char *curr;
	int prot, prot_temp;
	prot_temp = PROT_READ | PROT_WRITE;
	for(i = 0, ppntr = pheaders; i < phnum; ++i, ++ppntr) {

		if(ppntr->p_type != PT_LOAD || ppntr->p_memsz == 0) continue;
		curr = elf + ppntr->p_offset;

		size_t align = ppntr->p_vaddr % sysconf(_SC_PAGE_SIZE);
		size_t v_addr = ppntr->p_vaddr - align;
		size_t ofs = ppntr->p_offset - align; //compensate for additional padding at beginning of page
		void *end;
		//Map only the file data, do not map the BSS segments
		void *temp = (char*) mmap((void*) v_addr, align + ppntr->p_filesz, prot_temp, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
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
	return;
}

void exec_elf64(char *elf, Elf64_Ehdr *header, int argc, char **argv, char **envp) {


	//Actually load the segments into memory
	hpager_load_segments(elf, header->e_phnum, pheaders);
	Elf64_Shdr sheaders[header->e_shnum];
	uint16_t str_table_dex = header->e_shstrndx;
	if(str_table_dex == SHN_XINDEX && header->e_shnum > 0) 
		str_table_dex = (uint16_t)(sheaders[0].sh_link);

	// load_sheaders_64(elf, header, sheaders);
	
	Elf64_Addr entry_point = header->e_entry;
	virt_program_entry = entry_point;

	//setup stack
	setup_stack(argc, argv, envp, header);
	create_elf_tables(header, envp, argc, esp);


	struct sigaction action;
	setup_handlers(&action);
	go_to_start();
	
}

Elf64_Phdr *find_segment_for_addr(Elf64_Addr addr) {
	Elf64_Phdr *ph;
	int i;
	for(i = 0, ph = pheaders; i < elf_header->e_phnum; ++i, ++ph) {
		if(ph->p_type != PT_LOAD) continue;
		if((ph->p_vaddr <= addr) && ((ph->p_vaddr + ph->p_memsz) >= addr)) {
			return ph;
		}
	}
	return NULL;
}

void sigsegv_handler(int sig, siginfo_t *info, void *unused) {
	char *msg;
	Elf64_Addr fault_addr = (Elf64_Addr)info->si_addr;
	fprintf(segfault_out, "(my) Segmentation Fault: %p\n", (void *)fault_addr);
	if((void *)fault_addr == NULL) {
		msg = "(my) Segmentation Fault: Invalid memory access: 0x0.\n\n";
		fwrite(msg, 1, strlen(msg), segfault_out); 
		exit(1);
	}
	//We need to check whether or not this address falls into any of the pages marked as PT_LOAD
	int i;
	int target_segment = -1;
	Elf64_Phdr *target_phdr = NULL;
	target_phdr = find_segment_for_addr(fault_addr);
	if(target_phdr == NULL) {
		msg = "(my) Segmentation Fault: Bad memory address.\n\n";
		fwrite(msg, 1, strlen(msg), segfault_out);
		exit(1);
	}
	//else we load a single page from the segment defined by target_phdr
	void *page = map_page_from_vaddr(fault_addr, target_phdr);
	Elf64_Addr address_in_file = fault_addr - target_phdr->p_vaddr + target_phdr->p_offset;
	map_page_from_vaddr(fault_addr, target_phdr);
	if(fault_addr < target_phdr->p_vaddr + target_phdr->p_filesz) {
		Elf64_Addr address_in_file = fault_addr - target_phdr->p_vaddr + target_phdr->p_offset;
		assert(*(int *)(elf_memory + address_in_file) == *(int *)(fault_addr));
	} else {
		assert(*(int *)(fault_addr) == 0);
	}
	//Map additional pages based on simple heuristic
	if(PAGES_PER_FAULT > 1) {
		//try the next page over
		
		Elf64_Addr next_page = ELF_PAGESTART(fault_addr + PAGE_SIZE + 1);
		target_phdr = find_segment_for_addr(next_page);
		if(target_phdr) 
			map_page_from_vaddr(next_page, target_phdr);
		
	}
	if(PAGES_PER_FAULT > 2) {
		//try the previous page
		
		Elf64_Addr prev_page = ELF_PAGESTART(fault_addr - PAGE_SIZE);
		target_phdr = find_segment_for_addr(prev_page);
		if(target_phdr) 
			map_page_from_vaddr(prev_page, target_phdr);		
	}
	msg = "(my) Segmentation Fault: Fault Resolved.\n\n";
	fwrite(msg, 1, strlen(msg), segfault_out);
	return;
}

void setup_handlers(struct sigaction *action) {
	action->sa_flags = SA_SIGINFO | SA_RESTART;
	action->sa_sigaction = sigsegv_handler;
	if(sigaction(SIGSEGV, action, NULL) == -1)
		handle_error("(hpager.c: setup_handlers) call to sigaction failed.\n\n");
}



void load_string_table(Elf64_Ehdr *header, Elf64_Shdr sheaders[]) {
	//Assume string table is provided under header->e_shsrndx directly, not supporting link entry.
	int string_section_idex = header->e_shstrndx;
	assert(string_section_idex != SHN_UNDEF && string_section_idex < SHN_XINDEX);
	Elf64_Shdr string_table_header = sheaders[string_section_idex];
	assert(string_table_header.sh_type == SHT_STRTAB);
	char *string_data = (char *)(elf_memory + string_table_header.sh_offset);
	section_name_data = string_data;
	assert(*string_data == '\0');
	assert(*(string_data + string_table_header.sh_size - 1) == '\0');

	num_strings = 2; //null at beginning and end
	char *curr = string_data + 1;
	size_t len;
	while(*curr != '\0') {
		len = strlen(curr);
		curr += len + 1;
		++num_strings;
	}
	string_table = malloc(sizeof(char *)*num_strings);
	if(string_table == NULL) 
		handle_error("(hpager.c: load_string_table): String table malloc failed;\n");
	int index = 1;
	curr = string_data + 1;
	while(*curr != '\0') {
		len = strlen(curr);
		curr += len + 1;
		string_table[index] = curr;
		++index;
	}
	string_table[0] = string_data;
	string_table[num_strings - 1] = curr;
}

void print_string_table() {
	for(int i = 0; i < num_strings; ++i) {
		printf("%s\n", string_table[i]);
	}
}

int main(int argc, char *argv[], char *envp[]) {

		int exec_argc;
	char **exec_argv;
	if(argc > 1 && strcmp(argv[1], "-sig_out") == 0) {
		segfault_out = fopen(argv[2], "w");
		if(!segfault_out)
			handle_error("(hpager.c: main): failed to open segv_out file.\n");
		fprintf(segfault_out, "Initialized as segfault tracer.\n");
		exec_argc = argc - 3;
		exec_argv = &argv[3];
	} else {
		exec_argc = argc - 1;
		exec_argv = &argv[1];
		segfault_out = stderr;
	}

	if(argc <= 1) handle_error("Usage: Require an executable to load.\n");

	int fd = open(exec_argv[0], O_RDONLY);
	if((fd == -1))
		handle_error("(hpager.c: main): Failed to open executable.\n");

	elf_fd = fd;
	elf_memory = load_elf_file(fd);

	Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));
	if(!header) 
		handle_error("(hpager.c: main): Failed to mallocate pheaders.\n");	
	elf_header = header;
	read_elf_header_64(elf_memory, header);
	if(!is_elf(header->e_ident)) {
		handle_error("(hpager.c: main): Invalid ELF header.\n");
	}

	

	pheaders = malloc(sizeof(Elf64_Phdr)*header->e_phnum);
	if(!pheaders)
		handle_error("(hpager.c: main): Failed to mallocate pheaders.\n");
	load_pheaders_64(elf_memory, header, pheaders);
	if(header->e_phnum != 0) {
		program_header_address = pheaders[0].p_vaddr + header->e_phoff;
	}
	
	if(check_overlap(envp, header->e_entry)) 
		handle_error("Cannot load ourself!\n");

	Elf64_Shdr sheaders[header->e_shnum];
	load_sheaders_64(elf_memory, header, sheaders);
	load_string_table(header, sheaders);	
	switch(header->e_type) {
		case ET_EXEC:
			//preload .text and .data sections
			exec_elf64(elf_memory, header, exec_argc, exec_argv, envp);	
			break;
		case ET_DYN: 
			exec_elf64(elf_memory, header, exec_argc, exec_argv, envp);
			break;
		default:
			break;
	}
	

}