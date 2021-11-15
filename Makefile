CC ?= gcc
CFLAGS += -Ofast -fPIC -fvisibility=hidden -flto -finline-functions #-fprofile-use=program.gcda #-fprofile-generate #-g -fsanitize=address 
LDFLAGS += -flto
PREFIX ?= /usr

ODIR=build
SDIR=src

_OBJ = cfg.o disassembler.o tnt_cache.o decoder.o libxdc.o mmh3.o trace_cache.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

default: tester_dyn tester_static

$(ODIR)/%.o: $(SDIR)/%.c $(SDIR)/*.h libxdc.h
	mkdir -p build
	$(CC) -c -o $@ $< $(CFLAGS)

dynlib: $(OBJ)
	$(CC) $^ -o build/libxdc.so -shared $(CFLAGS) $(LDFLAGS) -l:libcapstone.so.4

staticlib: $(OBJ)
	$(AR) rcs build/libxdc.a $^

tester_dyn: dynlib test/*.c test/*.h
	$(CC) test/tester.c test/page_cache.c test/helper.c -o build/$@ -Itest/ -I./ -Lbuild/ $(CFLAGS) $(LDFLAGS) -lxdc -l:libcapstone.so.4

tester_static: staticlib test/*.c test/*.h
	$(CC) test/tester.c test/page_cache.c test/helper.c -o build/$@ -Itest/ -I./ $(CFLAGS) $(LDFLAGS) -Lbuild/ -l:libxdc.a -l:libcapstone.so.4

install: dynlib staticlib
	mkdir -p $(PREFIX)/include $(PREFIX)/lib
	install -m0644 libxdc.h $(PREFIX)/include/
	install -m0755 build/libxdc.so $(PREFIX)/lib/
	install -m0755 build/libxdc.a $(PREFIX)/lib/

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o build/*
