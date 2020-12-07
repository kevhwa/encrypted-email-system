CC = gcc
CFLAGS = -g -Wall -std=c11
LDFLAGS = -g
LDLIBS = -lssl -lcrypto

.PHONY: all

all: bin/getcert bin/server

bin/getcert: src/client_get_cert.o src/create_ctx.o
	$(CC) $(LDFLAGS) $(LDLIBS) src/client_get_cert.o src/create_ctx.o -o bin/getcert

bin/server: src/server.o src/create_ctx.o
	$(CC) $(LDFLAGS) $(LDLIBS) src/server.o src/create_ctx.o -o bin/server

client_get_cert.o: src/client_get_cert.c src/create_ctx.h 
	$(CC) $(LDFLAGS) $(LDLIBS) -c src/client_get_cert.c

server.o: src/server.c src/create_ctx.h
	$(CC) $(LDFLAGS) $(LDLIBS) -c src/server.c

create_ctx.o: src/create_ctx.c src/create_ctx.h
	$(CC) $(CFLAGS) -c src/create_ctx.c

