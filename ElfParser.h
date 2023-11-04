#ifndef ELF_PARSER_H
#define ELF_PARSER_H
#include <elf.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include "Common.h"

void read_elf_header_64(int fd, Elf64_Ehdr *header);
int is_elf(unsigned char e_ident[]);
void load_pheaders_64(int fd, Elf64_Ehdr *header, Elf64_Phdr pheaders[]);
void print_program_headers(Elf64_Half phnum, Elf64_Phdr pheaders[]);
#endif