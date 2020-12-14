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
	EVP_PKEY *p_key = generate_key(uname);
	X509_REQ *cert_req = generate_cert_req(p_key, uname, &cert_size);

	printf("size of cert request: %d\n", cert_size);
	
	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "./client-dir/%s/cert_req.pem", uname);
	FILE* cert_file = fopen(path_buf, "r");
	if (!cert_file) {
		printf("Could not open file for cert request.\n");
	}

	char cert_buf[2000];
	fread(cert_buf, sizeof(cert_buf), 1, cert_file);
	printf(cert_buf);

	sprintf(content_buf, "%s\n%s\n", uname, pass);
	sprintf(obuf, "POST /getcert HTTP/1.0\nContent-Length:%lu\n%s\n%s\n",
			strlen(content_buf) + cert_size, content_buf);

	printf("%s\n", obuf);

	SSL_write(ssl, obuf, strlen(obuf));
	SSL_write(ssl, cert_buf, cert_size);
	
	while ((ilen = SSL_read(ssl, ibuf, sizeof ibuf - 1)) > 0) {
		ibuf[ilen] = '\0';
		fprintf(stdout, "%s", ibuf);
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


X509_REQ *generate_cert_req(EVP_PKEY *p_key, char *username, int *size) {
    X509_REQ *p_x509_req = NULL;

    if (p_key == NULL) {
        printf("No EVP_PKEY provided\n");
    }

    if ((p_x509_req = X509_REQ_new()) == NULL) {
        printf("Failed to create a new X509 REQ\n");
        goto CLEANUP;
    }

    if (X509_REQ_set_pubkey(p_x509_req, p_key) < 0) {
        printf("failed to set pubic key\n");
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        goto CLEANUP;
    }

    if (0 > X509_REQ_sign(p_x509_req, p_key, EVP_sha256())) {
        printf("failed to sign the certificate\n");
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        goto CLEANUP;
    }

    CLEANUP:
    EVP_PKEY_free(p_key);

	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "./client-dir/%s/cert_req.pem", username);

	FILE *x509_file = fopen(path_buf, "wb");
    if(!x509_file) {
        printf("Unable to open cert req file for writing.\n");
        return NULL;
    }
    
    /* Write the certificate to disk. */
    int ret = PEM_write_X509_REQ(x509_file, p_x509_req);
    fclose(x509_file);

	struct stat st;
	stat(path_buf, &st);
	*size = st.st_size;

    return p_x509_req;
}

/* Generates a 2048-bit RSA key. */
EVP_PKEY *generate_key(char *username) {
    /* Allocate memory for the EVP_PKEY structure. */
    // EVP_PKEY *pkey = EVP_PKEY_new();
    // if(!pkey) {
    //     printf("Unable to create EVP_PKEY structure.\n");
    //     return NULL;
    // }
    
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;
 	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	 if (!ctx) {

	 }
 	if (EVP_PKEY_keygen_init(ctx) <= 0){
		 
	 }
 	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {

	 }
 	if (EVP_PKEY_keygen(ctx, &pkey) <= 0){
		 
	 }

    /* Generate the RSA key and assign it to pkey. */
	// RSA *rsa = RSA_new();
    // RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    // if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
	// 	printf("Unable to generate RSA key\n.");
    //     EVP_PKEY_free(pkey);
    //     return NULL;
    // }
	
	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "client-dir/%s/private.key", username);

	printf("%s\n", path_buf);

	FILE* pkey_file = fopen(path_buf, "wb");
	if (!pkey_file) {
		printf("Could not open file for private key.\n");
	}

	PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(pkey_file);	
    return pkey;
}
