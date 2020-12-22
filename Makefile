CC = gcc
CFLAGS = -g -Wall -std=c11
LDFLAGS = -g

ifeq ($(shell uname -s),Darwin)
	LDLIBS = -lssl -lcrypto
else
	LDLIBS = -lssl -lcrypto -lcrypt
endif

.PHONY: all clean install-basic install-all

install-basic: clean all
	./bin/install-basic.sh $(DEST)

install-with-security: clean all
	./bin/install-basic.sh $(DEST)
	sudo ./bin/install-users.sh
	./bin/install-priv.sh $(DEST)
	sudo ./bin/install-sandbox.sh $(DEST)

all: bin/getcert bin/changepw bin/server bin/sendmsg bin/recvmsg

bin/getcert: src/client_get_cert.o src/create_ctx.o src/user_io.o
	$(CC) $(LDFLAGS) src/client_get_cert.o src/create_ctx.o src/user_io.o -o bin/getcert $(LDLIBS)

bin/changepw: src/client_changepw.o src/create_ctx.o src/user_io.o
	$(CC) $(LDFLAGS) src/client_changepw.o src/create_ctx.o src/user_io.o -o bin/changepw $(LDLIBS)

bin/sendmsg: src/client_send_msg.o src/create_ctx.o src/user_io.o src/custom_utils.o src/request_handler.o
	$(CC) $(LDFLAGS) src/client_send_msg.o src/create_ctx.o src/user_io.o src/custom_utils.o src/request_handler.o -o bin/sendmsg $(LDLIBS)

bin/recvmsg: src/client_recv_msg.o src/create_ctx.o src/user_io.o src/custom_utils.o
	$(CC) $(LDFLAGS) src/client_recv_msg.o src/create_ctx.o src/user_io.o src/custom_utils.o -o bin/recvmsg $(LDLIBS)

bin/server: src/server.o src/create_ctx.o src/request_handler.o
	$(CC) $(LDFLAGS) src/server.o src/create_ctx.o src/request_handler.o -o bin/server $(LDLIBS)

client_changepw.o: src/client_changepw.c src/create_ctx.h src/user_io.h
	$(CC) $(CFLAGS) -c src/client_changepw.c $(LDLIBS)

client_get_cert.o: src/client_get_cert.c src/create_ctx.h src/user_io.h
	$(CC) $(CFLAGS) -c src/client_get_cert.c $(LDLIBS)

client_send_msg.o: src/client_send_msg.c src/create_ctx.h src/user_io.h src/custom_utils.h src/request_handler.h
	$(CC) $(CFLAGS) -c src/client_send_msg.c $(LDLIBS)

client_recv_msg.o: src/client_recv_msg.c src/create_ctx.h src/user_io.h src/custom_utils.h
	$(CC) $(CFLAGS) -c src/client_recv_msg.c $(LDLIBS)

request_handler.o: src/request_handler.c src/request_handler.h
	$(CC) $(CFLAGS) -c src/request_handler.c $(LDLIBS)

server.o: src/server.c src/create_ctx.h src/request_handler.h
	$(CC) $(CFLAGS) -c src/server.c $(LDLIBS)

create_ctx.o: src/create_ctx.c src/create_ctx.h
	$(CC) $(CFLAGS) -c src/create_ctx.c

user_io.o: src/user_io.c src/user_io.h
	$(CC) $(CFLAGS) -c src/create_ctx.c

custom_utils.o: src/custom_utils.c src/custom_utils.h
	$(CC) $(CFLAGS) -c src/custom_utils.c

clean:
	rm -f src/*.o bin/getcert bin/server bin/sendmsg bin/recvmsg
