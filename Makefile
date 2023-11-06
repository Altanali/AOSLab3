cc=gcc
elf_parser=ElfParser.c ElfParser.h
common=Common.h
lazy_loader=$(common) $(elf_parser) LazyLoader.c

LazyLoader: $(lazy_loader)
	$(cc) -g -static -Wl,-Ttext-segment=0x200000 $(lazy_loader) -o $@