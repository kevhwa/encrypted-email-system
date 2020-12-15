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

#define h_addr h_addr_list[0] /* for backward compatibility */

int tcp_connection(char *host_name, int port);
void print_usage_information();
EVP_PKEY *generate_key(char *username);
X509_REQ *generate_cert_req(EVP_PKEY *p_key, char *username, int *size);
void get_x509_req_as_str(char *uname, char *x509_buf, size_t buf_size);

int main(int argc, char **argv) {
	int err;
	char *s;
	SSL_CTX *ctx;
	int sock;

	int MAX_LENGTH = 20;
	char pass[MAX_LENGTH];
	char uname[MAX_LENGTH];

	if (get_username_password(argc, argv, pass, uname, MAX_LENGTH) < 0) {
		print_usage_information();
		exit(1);
	}

	// create the SSL context; note that no certificate
	// and private key are provided; this will run with username/password
	ctx = create_ctx_client(NULL, NULL, 0);

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

	int ilen;
	char ibuf[4096];
	char obuf[4096];
	char content_buf[200];
	int cert_size = 0;
	EVP_PKEY *p_key;

	// generate a rsa key pair
	if (!(p_key = generate_key(uname))) {
		fprintf(stderr, "Could not generate RSA keys.\n");
		exit(1);
	}

	// create a certificate request using newly created rsa_key_pair
	generate_cert_req(p_key, uname, &cert_size);
	char cert_buf[cert_size + 1];
	get_x509_req_as_str(uname, cert_buf, cert_size);

	// format content to sent to server
	sprintf(content_buf, "%s\n%s\n", uname, pass);
	sprintf(obuf, "POST /getcert HTTP/1.0\nContent-Length: %lu\n\n%s",
			strlen(content_buf) + cert_size, content_buf);

	// Prvoide content to server
	SSL_write(ssl, obuf, strlen(obuf));
	SSL_write(ssl, cert_buf, cert_size);

	// Get server response 	
	fprintf(stdout, "\nSERVER RESPONSE:\n");
	while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
		ibuf[ilen] = '\0';
		fprintf(stdout, "%s", ibuf);
	}

	// Clean Up
	EVP_PKEY_free(p_key);
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

/**
 * Print out usage information, if user did not provide the correct arguments
 * for the program.
 */
void print_usage_information() {
	fprintf(stderr,
			"Usage of this program requires specification of the following flag(s):\n"
					"* [-u] a valid username (required)\n"
					"* [-p] a valid password (optional, you will be prompted if not provided)\n"
					"Example usage: getcert -u username -p password\n\n");
}


/**
 * Generate a certificate request.
 */
X509_REQ* generate_cert_req(EVP_PKEY *p_key, char *username, int *size) {
	X509_REQ *p_x509_req = NULL;

	if (p_key == NULL) {
		printf("No EVP_PKEY provided\n");
	}

	if ((p_x509_req = X509_REQ_new()) == NULL) {
		printf("Failed to create a new X509 REQ\n");
		goto CLEANUP;
	}

	if (X509_REQ_set_pubkey(p_x509_req, p_key) < 0) {
		printf("Failed to set pubic key\n");
		X509_REQ_free(p_x509_req);
		p_x509_req = NULL;
		goto CLEANUP;
	}

	if (0 > X509_REQ_sign(p_x509_req, p_key, EVP_sha256())) {
		printf("Failed to sign the X509 REQ.\n");
		X509_REQ_free(p_x509_req);
		p_x509_req = NULL;
		goto CLEANUP;
	}

	CLEANUP: EVP_PKEY_free(p_key);

	// -- Save X509 REQ to a file, saving the size of content written -- 

	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "./client-dir/%s/cert_req.pem",
			username);

	FILE *x509_file = fopen(path_buf, "wb");
	if (!x509_file) {
		printf("Unable to open CSR file for writing.\n");
		X509_REQ_free(p_x509_req);
		return NULL;
	}

	int ret;
	if (!(ret = PEM_write_X509_REQ(x509_file, p_x509_req))) {
		printf("Attempt to save X509 REQ to file failed.\n");
	}
	fclose(x509_file);

	struct stat st;
	stat(path_buf, &st);
	*size = st.st_size;

	return p_x509_req;
}

/**
 * Opens a newly created X509 REQ file into a string. Once read,
 * deletes the CSR file, as it is no longer needed.
 */
void get_x509_req_as_str(char *uname, char *x509_buf, size_t buf_size) {

	// Open the newly saved cert_req.pm file, as char *
	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "./client-dir/%s/cert_req.pem", uname);
	FILE *cert_file = fopen(path_buf, "r");
	if (!cert_file) {
		printf("Could not open file for cert request.\n");
		return;
	}

	size_t content = fread(x509_buf, 1, buf_size - 1, cert_file);
	x509_buf[content] = '\0';

	fclose(cert_file);
	printf("READ CSR FROM FILE:\n%s\n", x509_buf);

	// delete the request now that we've read and are done with it
	int del = remove(path_buf);
	if (del != 0)
		printf("CSR file was not successfully removed.\n");
	return;
}

/**
 * Generate a 2048-bit RSA key and save to a file
 * under the specified username.
 */
EVP_PKEY* generate_key(char *username) {

	// --- create the RSA KEY ----
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx) {
		fprintf(stderr, "Could not create EVP_PKEY_ctx.\n");
		return NULL;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		fprintf(stderr, "Could not initialize public key algorithm context.\n");
		return NULL;
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
		fprintf(stderr, "Could not set the RSA key length for RSA key generation.\n");
		return NULL;
	}
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		fprintf(stderr, "Could not perform key generation operation.\n");
		return NULL;
	}

	// --- Save the RSA key to file ----

	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "client-dir/%s/private.key", username);

	FILE *pkey_file = fopen(path_buf, "wb");
	if (!pkey_file) {
		printf("Could not open and write private key to file.\n");
		EVP_PKEY_free(pkey);
		return NULL;
	}

	PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(pkey_file);

	// --- Return the private key ----	
	return pkey;
}
