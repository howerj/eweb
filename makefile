CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2 -std=c99 -Wmissing-prototypes -fwrapv

ifeq ($(OS),Windows_NT)
    OS := win
    LDFLAGS := -lws2_32
else # Assume Unix
    OS := unix
    LDFLAGS := -pthread
endif

.PHONY: all run clean

all: eweb simple

libeweb.a: eweb.o ${OS}.o
	ar rcs $@ $^
	ranlib $@

eweb: main.o libeweb.a
	${CC} ${CFLAGS} $^ ${LDFLAGS} -o $@

simple: simple.o libeweb.a
	${CC} ${CFLAGS} $^ ${LDFLAGS} -o $@

check:
	cppcheck --enable=all *.c

run: eweb
	cd content && ${TRACER} ../eweb -p 1234

clean:
	rm -vf *.o *.exe eweb simple

