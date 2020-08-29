IDIR =../include
CC=gcc
CFLAGS= -g -Ofast -fPIC -fvisibility=hidden -flto -finline-functions #-fprofile-use=program.gcda #-fprofile-generate #-g -fsanitize=address 
LDFLAGS=-flto

ODIR=build
SDIR=src
LDIR =build

_OBJ = cfg.o disassembler.o tnt_cache.o decoder.o libxdc.o mmh3.o trace_cache.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

default: tester_dyn tester_static

$(ODIR)/%.o: $(SDIR)/%.c $(SDIR)/*.h libxdc.h
	mkdir -p build
	$(CC) -c -o $@ $< $(CFLAGS)

dynlib: $(OBJ)
	$(CC) $^ -o build/libxdc.so -shared $(CFLAGS) $(LDFLAGS) -l:libcapstone.so.4 

staticlib: $(OBJ)
	ar rcs build/libxdc.a $^

tester_dyn: dynlib test/*.c test/*.h
	$(CC) test/tester.c test/page_cache.c test/helper.c -o build/tester -Itest/ -I./ -Lbuild/ -lxdc $(CFLAGS) $(LDFLGAS)

tester_static: staticlib test/*.c test/*.h
	$(CC) test/tester.c test/page_cache.c test/helper.c -o build/tester_static -Itest/ -I./ -Lbuild/ -l:libxdc.a -l:libcapstone.so.4 $(CFLAGS) $(LDFLAGS)

install: dynlib
	cp libxdc.h /usr/include/
	cp build/libxdc.so /usr/lib/

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o build/*
