CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2 -std=gnu99
LDFLAGS=-pthread

.PHONY: all run clean

all: eweb simple

eweb: eweb.o dwebsvr.o

simple: simple.o dwebsvr.o

run: eweb
	cd content && ../eweb 1234

clean:
	rm -vf *.o *.exe eweb simple

