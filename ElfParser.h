#ifndef ELF_PARSER_H
#define ELF_PARSER_H
#include <elf.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "Common.h"

#define STACK_SIZE_PAGES 10
#define PAGE_SIZE 4096
#define STACK_SIZE PAGE_SIZE*STACK_SIZE_PAGES
#define STACK_START 0x20000000	


//Macros taken from the Linux Kernel implemention (fs/binfmt_elf.c)
#define ELF_MIN_ALIGN	PAGE_SIZE
#define ELF_PAGESTART(_v) ((_v) & ~(int)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))
#define arch_align_stack(p) ((unsigned long)(p) & ~0xf)

#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) - (items))
#define STACK_ROUND(sp, items) \
	(((unsigned long) (sp - items)) &~ 15UL)
#define STACK_ALLOC(sp, len) (sp -= len)


char *load_elf_file(int fd);
void read_elf_header_64(char *elf, Elf64_Ehdr *header);
int is_elf(unsigned char e_ident[]);
void load_pheaders_64(char *elf, Elf64_Ehdr *header, Elf64_Phdr pheaders[]);
void print_program_headers(Elf64_Half phnum, Elf64_Phdr pheaders[]);
uint64_t calculate_load_size(Elf64_Half phnum, Elf64_Phdr pheaders[]);
void load_segments(char *elf, Elf64_Half phnum, Elf64_Phdr pheaders[], uint64_t load_size);
void load_sheaders_64(char *elf, Elf64_Ehdr *header, Elf64_Shdr sheaders[]);
void print_section_headers(Elf64_Half shnum, Elf64_Shdr sheaders[]);
#endif