CC=gcc

CFLAGS=-c 
all: hello

hello: mydump.o
	$(CC) mydump.o -o mydump -lpcap

mydump.o: mydump.c
	$(CC) $(CFLAGS) mydump.c

clean:
	rm -rf *o file