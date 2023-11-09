cc=gcc
elf_parser=ElfParser.c ElfParser.h
common=Common.h
apager=$(common) $(elf_parser) apager.c
dpager=$(common) $(elf_parser) dpager.c
hpager=$(common) $(elf_parser) hpager.c
PAGES_PER_FAULT=2

all: apager dpager hpager

apager: $(apager)
	$(cc) -g -static -Wl,-Ttext-segment=0x200000 $(apager) -o $@

dpager: $(dpager)
	$(cc) -g -static -Wl,-Ttext-segment=0x200000 $(dpager) -o $@

hpager: $(hpager)
	$(cc) -g -static -DPAGES_PER_FAULT=$(PAGES_PER_FAULT) -Wl,-Ttext-segment=0x200000 $(hpager) -o $@



hello_world_static: hello_world.c
	$(cc) -g -static hello_world.c -o hello_world_static