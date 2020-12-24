SHELL = /bin/bash
CC = gcc
CFLAGS = -g /usr/local/include/pcap/pcap.h -lpcap
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:%.c
	${CC}  $@.c -o $@ ${CFLAGS}
clean: ${EXE}
	rm -f ${EXE}
