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

#define STACK_SIZE_PAGES 8

char *load_elf_file(int fd);
void read_elf_header_64(char *elf, Elf64_Ehdr *header);
int is_elf(unsigned char e_ident[]);
void load_pheaders_64(char *elf, Elf64_Ehdr *header, Elf64_Phdr pheaders[]);
void print_program_headers(Elf64_Half phnum, Elf64_Phdr pheaders[]);
uint64_t calculate_load_size(Elf64_Half phnum, Elf64_Phdr pheaders[]);
void load_segments(char *elf, Elf64_Half phnum, Elf64_Phdr pheaders[], char *memory, uint64_t load_size);
void load_sheaders_64(char *elf, Elf64_Ehdr *header, Elf64_Shdr sheaders[]);
void print_section_headers(Elf64_Half shnum, Elf64_Shdr sheaders[]);
#endif