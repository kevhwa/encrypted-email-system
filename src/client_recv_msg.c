#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "create_ctx.h"
#include "user_io.h"

#define h_addr h_addr_list[0]  /* for backward compatibility */
#define TRUSTED_CA "trusted_ca/ca-chain.cert.pem"
#define CERT_LOCATION_TEMPLATE "mailboxes/%s/%s.cert.pem"
#define PRIVATE_KEY_TEMPLATE "mailboxes/%s/%s.private.key"

int tcp_connection(char *host_name, int port);


int main(int argc, char **argv) {
	int err;
	char *s;
	SSL_CTX *ctx;
	int sock;

	// figure out who the user is so that their certificate and key can be configured
	char username[32];
	if ((err = getlogin_r(username, 32))) {
		printf("Failed to determine identify of user.\n");
		exit(1);
	}

	char certificate_path[256];
	char private_key_path[256];
	sprintf(certificate_path, CERT_LOCATION_TEMPLATE, username, username);
	sprintf(private_key_path, PRIVATE_KEY_TEMPLATE, username, username);
	ctx = create_ctx_client(certificate_path, private_key_path, TRUSTED_CA, 1);

	// create the TCP socket
	if ((sock = tcp_connection("localhost", 8080)) < 0) {
		fprintf(stdout, "Could not create TCP socket...\n");
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

	char obuf[4096];
	char content_buf[200];
	int cert_size = 0;

	// -------- Provide content to server -------- //
	// sprintf(content_buf, "%s\n%s\n", uname, pass);
	// sprintf(obuf, "GET /sendmsg HTTP/1.0\nContent-Length: %lu\n\n%s",
	// 		strlen(content_buf) + cert_size, content_buf);

	// SSL_write(ssl, obuf, strlen(obuf));
	// SSL_write(ssl, cert_buf, cert_size);

	// --------- Get server response ---------- //
	char response_buf[4096];

	fprintf(stdout, "\nSERVER RESPONSE:\n");
	err = SSL_read(ssl, response_buf, sizeof(response_buf) - 1);
	response_buf[err] = '\0';

	if (strstr(response_buf, "200 Success")) {
		printf("Success!\n");
	} else {
		printf("Sorry!\n");
	}

	// ------- Clean Up -------- //
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
		fprintf(stdout, "Socket creation failed");
		return -1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	he = gethostbyname(host_name);
	memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
	if (connect(sock, (struct sockaddr*) &sin, sizeof sin) < 0) {
		fprintf(stdout, "Socket connection failed");
		return -1;
	}
	return sock;
}

