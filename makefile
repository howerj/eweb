CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2 -std=c99
LDFLAGS=-pthread
OS=unix

.PHONY: all run clean

all: eweb simple

eweb: eweb.o main.o ${OS}.o

simple: eweb.o simple.o ${OS}.o

check:
	cppcheck --enable=all *.c 

run: eweb
	cd content && ../eweb 1234

clean:
	rm -vf *.o *.exe eweb simple

