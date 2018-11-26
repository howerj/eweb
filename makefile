CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2 -std=c99
LDFLAGS=-pthread

.PHONY: all run clean

all: eweb simple

eweb: eweb.o main.o

simple: eweb.o simple.o

run: eweb
	cd content && ../eweb 1234

clean:
	rm -vf *.o *.exe eweb simple

