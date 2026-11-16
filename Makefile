# logslip. Build on the target, or elsewhere for the same architecture.
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra

.PHONY: all clean

all: logslip

logslip: logslip.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f logslip
