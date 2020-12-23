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
#define TRUSTED_CA "trusted_ca/ca-chain.cert.pem"

int tcp_connection(char *host_name, int port);
void print_usage_information();
EVP_PKEY *generate_key(char *username);
X509_REQ *generate_cert_req(EVP_PKEY *p_key, char *username, int *size);
void read_x509_req_from_file(char *uname, char *x509_buf, size_t buf_size);
int write_x509_req_to_file(X509_REQ *p_x509_req, char *path);
int write_x509_cert_to_file(char *x509, char *path);


int main(int argc, char **argv) {
	int err;
	char *s;
	SSL_CTX *ctx;
	int sock;

	int MAX_LENGTH = 20;
	char pass[MAX_LENGTH];
	char uname[MAX_LENGTH];
    char new_pass[MAX_LENGTH];

	if (get_username_password(argc, argv, pass, uname, MAX_LENGTH) < 0) {
		print_usage_information();
		exit(1);
	}

    // prompt user for a new password
	char msg[100];
	sprintf(msg, "Please provide a new password (less than %d characters): ", MAX_LENGTH);
    get_hidden_pw(msg, new_pass, MAX_LENGTH);
    while (strlen(new_pass) < 2 || strlen(new_pass) > 20) {
        printf("Your password is not a valid length (2-20 characters)");
        get_hidden_pw(msg, new_pass, MAX_LENGTH);
    }

	// create the SSL context; note that no certificate
	// and private key are provided; this will run with username/password
	ctx = create_ctx_client(NULL, NULL, TRUSTED_CA, 0);

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

	// -------- Create a RSA Key Pair and CSR -------- //
	char obuf[4096];
	char content_buf[200];
	int cert_size = 0;
	EVP_PKEY *p_key;


	if (!(p_key = generate_key(uname))) {
		fprintf(stderr, "Are you sure you submitted your username correctly?\n");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(sock);
		return 1;
	}

	// ------------ Generate CSR ------------- //
	generate_cert_req(p_key, uname, &cert_size);
	if (!cert_size) {
		fprintf(stderr, "Could not generate X509 certificate REQ.\n");
		EVP_PKEY_free(p_key);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(sock);
		return 2;
	}

	char cert_buf[cert_size + 1];
	read_x509_req_from_file(uname, cert_buf, cert_size);

	// -------- Provide content to server -------- //
	sprintf(content_buf, "%s\n%s\n%s\n", uname, pass, new_pass);
	sprintf(obuf, "POST /changepw HTTP/1.0\nContent-Length: %lu\n\n%s",
			strlen(content_buf) + cert_size, content_buf);

	SSL_write(ssl, obuf, strlen(obuf));
	SSL_write(ssl, cert_buf, cert_size);

	// --------- Get server response ---------- //
	char response_buf[4096];

	fprintf(stdout, "\nSERVER RESPONSE:\n");
	err = SSL_read(ssl, response_buf, sizeof(response_buf) - 1);
	response_buf[err] = '\0';

	if (strstr(response_buf, "200 Success")) {
		printf("Success!\n");

		char cert_buf[4096];
		err = SSL_read(ssl, cert_buf, sizeof(cert_buf) - 1);
		cert_buf[err] = '\0';

		printf("Certificate:\n%s\n", cert_buf);
		char path_buf[100];
		snprintf(path_buf, sizeof(path_buf), "mailboxes/%s/%s.cert.pem", uname,
				uname);
		if (!write_x509_cert_to_file(cert_buf, path_buf)) {
			printf("Could not save newly generated certificate to a local file.\n");
		}
	}
	else if (strstr(response_buf, "409 Conflict")) {
		printf("You have unread messages on the server. Please retrieve the messages before "
			"requesting a password change and new certificate.\n");
	}
	else {
		printf("Sorry, your certificate could not be generated.\n");
	}

	// ------- Clean Up -------- //
	EVP_PKEY_free(p_key);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	return 0;
}

/**
 * Wrties a X509 Certificate to file.
 * Certificate should be string, not a X509 struct.
 */
int write_x509_cert_to_file(char *x509, char *path) {
	
	FILE *p_file = NULL;
	if (!(p_file = fopen(path, "wb+"))) {
		printf("Failed to open file for X509 certificate\n");
		return 0;
	}

	int write = fwrite(x509, 1, strlen(x509) , p_file);
	fclose(p_file);

	if (write != strlen(x509)) {
		printf("Could not write X509 certificate to file\n");
		return 0;
	}	
	return 1;
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
		fprintf(stdout, "Socket connection failed.\n");
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
					"Example usage: changepw -u username -p password\n\n");
}


/**
 * Generate a certificate request.
 */
X509_REQ* generate_cert_req(EVP_PKEY *p_key, char *username, int *size) {
	X509_REQ *p_x509_req = NULL;
	X509_NAME *name = NULL;

	if (p_key == NULL) {
		printf("No EVP_PKEY provided\n");
	}

	// create new X509 REQ
	if ((p_x509_req = X509_REQ_new()) == NULL) {
		printf("Failed to create a new X509 REQ\n");
		goto CLEANUP;
	}

	// set the public key on the REQ
	if (X509_REQ_set_pubkey(p_x509_req, p_key) < 0) {
		printf("Failed to set pubic key\n");
		X509_REQ_free(p_x509_req);
		p_x509_req = NULL;
		goto CLEANUP;
	}

	// add information about the client to the CSR
	if ((name = X509_REQ_get_subject_name(p_x509_req)) == NULL) {
		printf("Failed to get subject name from REQ\n");
		X509_REQ_free(p_x509_req);
		p_x509_req = NULL;
		goto CLEANUP;
	}

	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			(const unsigned char*) username, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
			(const unsigned char*) "A Really Cool Organization", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
			(const unsigned char*) "US", -1, -1, 0);

	// Sign the REQ
	if (X509_REQ_sign(p_x509_req, p_key, EVP_sha256()) < 0) {
		printf("Failed to sign the X509 REQ.\n");
		X509_REQ_free(p_x509_req);
		p_x509_req = NULL;
		goto CLEANUP;
	}

	CLEANUP: EVP_PKEY_free(p_key);

	// -- Save X509 REQ to a file, saving the size of content written -- //
	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "mailboxes/%s/cert_req.pem",
			username);
	*size = write_x509_req_to_file(p_x509_req, path_buf);
	return p_x509_req;
}

/**
 * Saves X509 REQ to file, returns the number of bytes in the written REQ.
 */
int write_x509_req_to_file(X509_REQ *p_x509_req, char *path) {

	if (!p_x509_req) {
		return 0;
	}

	FILE *x509_file = fopen(path, "wb");
	if (!x509_file) {
		printf("Unable to open CSR file for writing.\n");
		X509_REQ_free(p_x509_req);
		return 0;
	}

	int ret;
	if (!(ret = PEM_write_X509_REQ(x509_file, p_x509_req))) {
		printf("Attempt to save X509 REQ to file failed.\n");
		return 0;
	}
	fclose(x509_file);

	struct stat st;
	stat(path, &st);
	return st.st_size;
}

/**
 * Opens a newly created X509 REQ file into a string. Once read,
 * deletes the CSR file, as it is no longer needed.
 */
void read_x509_req_from_file(char *uname, char *x509_buf, size_t buf_size) {

	// Open the newly saved cert_req.pm file, as char *
	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "mailboxes/%s/cert_req.pem", uname);
	FILE *cert_file = fopen(path_buf, "rb+");
	if (!cert_file) {
		printf("Could not open file for cert request.\n");
		return;
	}

	size_t content = fread(x509_buf, 1, buf_size - 1, cert_file);
	x509_buf[content] = '\0';
	fclose(cert_file);

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
	snprintf(path_buf, sizeof(path_buf), "mailboxes/%s/%s.private.key", username, username);

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
