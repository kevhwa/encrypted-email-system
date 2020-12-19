CC = gcc
CFLAGS = -g -Wall -std=c11
LDFLAGS = -g
LDLIBS = -lssl -lcrypto -lcrypt # needs to be added if using linux

.PHONY: all clean install-basic install-all

install-basic: clean all
	./bin/install-basic.sh $(DEST)

install-with-security: clean all
	./bin/install-basic.sh $(DEST)
	sudo ./bin/install-users.sh
	sudo ./bin/install-priv.sh $(DEST)
	sudo ./bin/install-sandbox.sh $(DEST)

all: bin/getcert bin/changepw bin/server

bin/getcert: src/client_get_cert.o src/create_ctx.o src/user_io.o
	$(CC) $(LDFLAGS) src/client_get_cert.o src/create_ctx.o src/user_io.o -o bin/getcert $(LDLIBS)

bin/changepw: src/client_changepw.o src/create_ctx.o src/user_io.o
	$(CC) $(LDFLAGS) src/client_changepw.o src/create_ctx.o src/user_io.o -o bin/changepw $(LDLIBS)

bin/server: src/server.o src/create_ctx.o
	$(CC) $(LDFLAGS) src/server.o src/create_ctx.o -o bin/server $(LDLIBS)

client_changepw.o: src/client_changepw.c src/create_ctx.h src/user_io.h
	$(CC) $(CFLAGS) -c src/client_changepw.c $(LDLIBS)

client_get_cert.o: src/client_get_cert.c src/create_ctx.h src/user_io.h
	$(CC) $(CFLAGS) -c src/client_get_cert.c $(LDLIBS)

server.o: src/server.c src/create_ctx.h
	$(CC) $(CFLAGS) -c src/server.c $(LDLIBS)

create_ctx.o: src/create_ctx.c src/create_ctx.h
	$(CC) $(CFLAGS) -c src/create_ctx.c

user_io.o: src/user_io.c src/user_io.h
	$(CC) $(CFLAGS) -c src/create_ctx.c

clean:
	rm -f src/*.o bin/getcert bin/server
