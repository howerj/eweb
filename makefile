CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2 -std=c99 -Wmissing-prototypes -fwrapv
LDFLAGS=-pthread
OS=unix

.PHONY: all run clean

all: eweb simple

libeweb.a: eweb.o ${OS}.o
	ar rcs $@ $^
	ranlib $@

eweb: eweb.o main.o ${OS}.o

simple: eweb.o simple.o ${OS}.o

check:
	cppcheck --enable=all *.c 

run: eweb
	cd content && ${TRACER} ../eweb -p 1234

clean:
	rm -vf *.o *.exe eweb simple

