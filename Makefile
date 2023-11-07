cc=gcc
elf_parser=ElfParser.c ElfParser.h
common=Common.h
apager=$(common) $(elf_parser) apager.c

apager: $(apager)
	$(cc) -g -static -Wl,-Ttext-segment=0x200000 $(apager) -o $@



hello_world_static: hello_world.c
	$(cc) -g -static hello_world.c -o hello_world_static