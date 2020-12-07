#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "create_ctx.h"

int tcp_connection(char *host_name, int port);

/*
 * Compile with -lssl -lcrypto
 *
 */
int main(int argc, char **argv) {
	int err;
	char *s;
	SSL_CTX *ctx;
	int sock;

	// create the SSL context
	ctx = create_ctx_client(NULL, NULL, 0);

	// create the TCP socket
	if ((sock = tcp_connection("localhost", 10101)) < 0) {
		return 2;
	}

	// connect the SSL socket
	SSL *ssl = SSL_new(ctx);
	BIO *sbio = BIO_new(BIO_s_socket());
	BIO_set_fd(sbio, sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);

	err = SSL_connect(ssl);
	if (err != 1) {
		switch (SSL_get_error(ssl, err)) {
		case SSL_ERROR_NONE:
			s = "SSL_ERROR_NONE";
			break;
		case SSL_ERROR_ZERO_RETURN:
			s = "SSL_ERROR_ZERO_RETURN";
			break;
		case SSL_ERROR_WANT_READ:
			s = "SSL_ERROR_WANT_READ";
			break;
		case SSL_ERROR_WANT_WRITE:
			s = "SSL_ERROR_WANT_WRITE";
			break;
		case SSL_ERROR_WANT_CONNECT:
			s = "SSL_ERROR_WANT_CONNECT";
			break;
		case SSL_ERROR_WANT_ACCEPT:
			s = "SSL_ERROR_WANT_ACCEPT";
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			s = "SSL_ERROR_WANT_X509_LOOKUP";
			break;
		case SSL_ERROR_WANT_ASYNC:
			s = "SSL_ERROR_WANT_ASYNC";
			break;
		case SSL_ERROR_WANT_ASYNC_JOB:
			s = "SSL_ERROR_WANT_ASYNC_JOB";
			break;
		case SSL_ERROR_SYSCALL:
			s = "SSL_ERROR_SYSCALL";
			break;
		case SSL_ERROR_SSL:
			s = "SSL_ERROR_SSL";
			break;
		}
		fprintf(stderr, "SSL error: %s\n", s);
		ERR_print_errors_fp(stderr);
		return 3;
	}

	int ilen;
	char ibuf[512];
	char *obuf = "GET / HTTP/1.0\n\n";

	SSL_write(ssl, obuf, strlen(obuf));
	while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
		ibuf[ilen] = '\0';
		printf("%s", ibuf);
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	return 0;
}

/**
 * Initializes the TCP connection based on provided hostname
 * and port.
 */
int tcp_connection(char *host_name, int port) {

	struct sockaddr_in sin;
	int sock;
	struct hostent *he;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	he = gethostbyname(host_name);
	memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
	if (connect(sock, (struct sockaddr*) &sin, sizeof sin) < 0) {
		perror("connect");
		return -1;
	}
	return sock;
}

