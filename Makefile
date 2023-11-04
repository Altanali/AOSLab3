cc=gcc
elf_parser=ElfParser.c ElfParser.h
common=Common.h
lazy_loader=$(common) $(elf_parser) LazyLoader.c

LazyLoader: $(lazy_loader)
	$(cc) $(lazy_loader) -o $@