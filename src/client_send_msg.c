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
#include <openssl/cms.h>

#include "create_ctx.h"
#include "user_io.h"

#define h_addr h_addr_list[0] /* for backward compatibility */
#define TRUSTED_CA "trusted_ca/ca-chain.cert.pem"
#define SERVER_PORT 8081
#define CERT_LOCATION_TEMPLATE "mailboxes/%s/%s.cert.pem"
#define PRIVATE_KEY_TEMPLATE "mailboxes/%s/%s.private.key"
#define ENCRYPTED_MSG_TEMPLATE "mailboxes/%s/tmp_encrypted_msg.txt"
#define SIGNED_MSG_TEMPLATE "mailboxes/%s/tmp_signed_msg.txt"
#define RECIPIENT_CERT_TEMPLATE "mailboxes/%s/tmp_%s.pem"

int tcp_connection(char *host_name, int port);
void print_usage_information();
char* receive_ssl_response(SSL *ssl);
CertificatesHandler* parse_certificates(char* body);
void free_certificates_handler(CertificatesHandler* certificates_handler);
int encrypt_message(char *msg_path, char *rcpt_cert_path, char *encrypted_msg_path);
int sign_encrypted_message(char *encrypted_msg_path, char *signer_cert_path, 
		char *signer_private_key, char *signed_msg_path);

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

	int MAX_RCPT_LENGTH = 20;
	int MAX_RCPTS_LENGTH = 190;
	int MAX_PATH_LENGTH = 50;

	char path[MAX_PATH_LENGTH];
	char rcpts[MAX_RCPTS_LENGTH];

	if (get_sendmsg_args(argc, argv, path, rcpts, MAX_PATH_LENGTH, 
			MAX_RCPTS_LENGTH, MAX_RCPTS_LENGTH) < 0) {
		print_usage_information();
		exit(1);
	}
	
	// -------- Make sure file can be read -------- //
	FILE* fp = fopen(path, "r");
	if (fp == NULL) {
		printf("Error: file cannot be opened or read");
		return 2;
	}

	// create the TCP socket
	if ((sock = tcp_connection("localhost", SERVER_PORT)) < 0) {
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

	// -------- Provide content to server -------- //
	char obuf[4096];
	sprintf(obuf, "GET /certificates HTTP/1.0\nContent-Length: %lu\n\n%s",
			strlen(rcpts), rcpts);

	SSL_write(ssl, obuf, strlen(obuf));

	// --------- Get server response ---------- //
	char *server_response = receive_ssl_response(ssl);
	CertificatesHandler *certs_handler = NULL;

	if (server_response) {
		printf("Received recipient certificates!\n");
		// char *file_data = get_file_data(fp);
		certs_handler = parse_certificates(server_response);
		if (certs_handler != NULL) {
			if (certs_handler->num == 0) {
				printf("No valid recipients found.\n");
			} else {
				FILE *tmpfile;
				char path_buf[100];
				for (int i = 0; i < certs_handler->num; i++) {
					memset(path_buf, '\0', sizeof(path_buf));
					snprintf(path_buf, sizeof(path_buf), RECIPIENT_CERT_TEMPLATE,
							certs_handler->recipients[i],
							certs_handler->recipients[i]);

					tmpfile = fopen(path_buf, "w");
					fwrite(certs_handler->certificates[i], sizeof(char),
							sizeof(certs_handler->certificates[i]), tmpfile);
					fclose(tmpfile);
				}
			}
			free_certificates_handler(certs_handler);
		} else {
			printf("Could not parse certificates in response "
					"message received from server.\n");
		}
		free(server_response);
	} else {
		printf("Could not receive recipient certificates.\n");
		goto CLEANUP;
	}

	// ------ Encrypt messages and send them to the server----- //
	for (int i = 0; i < certs_handler->num; i++) {

		char encrypt_msg_path_buf[128];
		sprintf(encrypt_msg_path_buf, ENCRYPTED_MSG_TEMPLATE, username);

		char rcpt_cert_buf[128];
		snprintf(rcpt_cert_buf, sizeof(rcpt_cert_buf), RECIPIENT_CERT_TEMPLATE,
				certs_handler->recipients[i], certs_handler->recipients[i]);

		if (encrypt_message(path, rcpt_cert_buf, encrypt_msg_path_buf)) {
			fprintf(stderr, "Encryption step failed for %s\n", rcpt_cert_buf);
			goto CLEANUP;
		}

		char signed_msg_path_buf[128];
		sprintf(signed_msg_path_buf, SIGNED_MSG_TEMPLATE, username);
		if (sign_encrypted_message(encrypt_msg_path_buf, certificate_path,
				private_key_path, signed_msg_path_buf)) {
			fprintf(stderr, "Digital signature step failed...\n");
			goto CLEANUP;
		}

		// ----- Send the content in signed_msg_path_buf to the server ------//
		// read in signed, encrypted content from file
		FILE *fp;
		if (!(fp = fopen(signed_msg_path_buf, "rb+"))) {
			fprintf(stderr,"Could not open digitally signed and encrypted message\n");
			goto CLEANUP;
		}
		fseek(fp, 0L, SEEK_END);     // go to the end of the file
		int n_bytes = ftell(fp);     // get the number of bytes
		fseek(fp, 0L, SEEK_SET);     // reset to beginning of file

		char file_buf[n_bytes + 1];
		size_t content = fread(file_buf, sizeof(char), n_bytes, fp);
		file_buf[content] = '\0';
		fclose(fp);

		// send the content to server... content formatted as:
		//
		// POST /newmsg HTTP/1.0
		// Content-Length: X
		//
		// sender
		// recipient
		// encrypted_msg_content....
		char content_buf[128 + n_bytes];
		int body_len = strlen(certs_handler->recipients[i]) + strlen(username) + strlen(file_buf);
		sprintf(content_buf,
				"POST /sendmsg HTTP/1.0\nContent-Length: %d\n\n%s\n%s\n%s",
				body_len, username, certs_handler->recipients[i], file_buf);

		SSL_write(ssl, content_buf, strlen(content_buf));
	}
	// ------- Clean Up -------- //
	CLEANUP:
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
 * Digitally signs an encrypted message content with the sender's private key 
 * Returns 0 if success, 1 if failure. The resultant digitally signed message 
 * will be saved to sign_msg_path.
 * 
 * Function code sourced from openssl demo file provided for project.
 */
int sign_encrypted_message(char *encrypted_msg_path, char *signer_cert_path,
		char *signer_private_key, char *signed_msg_path) {
	BIO *in = NULL, *out = NULL, *tbio = NULL;
	X509 *scert = NULL;
	EVP_PKEY *skey = NULL;
	CMS_ContentInfo *cms = NULL;
	int ret = 1;
	int flags = CMS_DETACHED | CMS_STREAM;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* Read in signer certificate and private key */
	tbio = BIO_new_file(signer_cert_path, "r");
	if (!tbio) {
		fprintf(stderr, "Could not open signer certificate from %s.\n",
				signer_cert_path);
		goto err;
	}
	scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
	BIO_reset(tbio);

	// not sure how the private key gets read from BIO in the provided example
	// so reading the private key separately
	// skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
	FILE *fp = fopen(signer_private_key, "rb+");
	skey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
	if (!scert || !skey) {
		fprintf(stderr, "Could not read in certificate and private key contents\n");
		goto err;
	}
	fclose(fp);

	/* Open content being signed */
	in = BIO_new_file(encrypted_msg_path, "r");
	if (!in) {
		fprintf(stderr, "Could not open content to be digitally signed\n");
		goto err;
	}
	/* Sign content */
	cms = CMS_sign(scert, skey, NULL, in, flags);
	if (!cms) {
		fprintf(stderr, "Could not sign message content\n");
		goto err;
	}

	out = BIO_new_file(signed_msg_path, "w");
	if (!out) {
		fprintf(stderr, "Could not open new file to save digitally signed messsage\n");
		goto err;
	}
	if (!(flags & CMS_STREAM))
		BIO_reset(in);

	/* Write out S/MIME message */
	if (!SMIME_write_CMS(out, cms, in, flags)) {
		fprintf(stderr, "Could not write digitally signed message to file\n");
		goto err;
	}
	ret = 0;

	err: if (ret) {
		fprintf(stderr, "Message content could not be digitally signed\n");
		ERR_print_errors_fp(stderr);
	}
	CMS_ContentInfo_free(cms);
	X509_free(scert);
	EVP_PKEY_free(skey);
	BIO_free(in);
	BIO_free(out);
	BIO_free(tbio);
	return ret;
}

/**
 * Encrypts a message located in a specified file using a recipient certificate
 * and saves the encrypted message to a new file. Returns 0 if
 * the encryption was successful, else 1. The resultant encrypted message will 
 * be saved to encrypted_msg_path.
 * 
 * Function code sourced from openssl demo file provided for project.
 */
int encrypt_message(char *msg_path, char *rcpt_cert_path, char *encrypted_msg_path) {
	BIO *in = NULL, *out = NULL, *tbio = NULL;
	X509 *rcert = NULL;
	STACK_OF(X509) *recips = NULL;
	CMS_ContentInfo *cms = NULL;
	int ret = 1;
	int flags = CMS_STREAM;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* Read in recipient certificate */
	tbio = BIO_new_file(rcpt_cert_path, "rb+");
	if (!tbio) {
		fprintf(stderr, "Could not open recipient certificate at %s\n",
				rcpt_cert_path);
		goto err;
	}

	rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
	if (!rcert) {
		fprintf(stderr, "Could not read recipient X509 from TBIO\n");
		goto err;
	}

	/* Create recipient STACK and add recipient cert to it */
	recips = sk_X509_new_null();
	if (!recips || !sk_X509_push(recips, rcert)) {
		fprintf(stderr, "Could not add recipient cert to stack\n");
		goto err;
	}

	/*
	 * sk_X509_pop_free will free up recipient STACK and its contents so set
	 * rcert to NULL so it isn't freed up twice.
	 */
	rcert = NULL;

	/* Open content being encrypted */
	in = BIO_new_file(msg_path, "r");
	if (!in) {
		fprintf(stderr, "Could not open message content to be encrypted.\n");
		goto err;
	}

	/* encrypt content */
	cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
	if (!cms) {
		fprintf(stderr, "Could not encrypt content to CMS\n");
		goto err;
	}

	out = BIO_new_file(encrypted_msg_path, "w");
	if (!out) {
		fprintf(stderr, "Could not open new encrypted message file\n");
		goto err;
	}

	/* Write out S/MIME message to file */
	if (!SMIME_write_CMS(out, cms, in, flags)) {
		fprintf(stderr, "Could not write encrypted content to file\n");
		goto err;
	}
	ret = 0;

	err: if (ret) {
		fprintf(stderr, "Data could not be encrypted...\n");
		ERR_print_errors_fp(stderr);
	}
	CMS_ContentInfo_free(cms);
	X509_free(rcert);
	sk_X509_pop_free(recips, X509_free);
	BIO_free(in);
	BIO_free(out);
	BIO_free(tbio);
	return ret;
}

/**
 * Print out usage information, if user did not provide the correct arguments
 * for the program.
 */
void print_usage_information() {
	fprintf(stderr,
			"Usage of this program requires specification of the following flag(s):\n"
					"* [-f] a valid path for the file to be sent\n"
					"* [-r] a list of recipient usernames for the message\n"
					"Example usage: sendmsg -f ./test.txt -r recpt1 recpt2 recpt3\n\n");
}

/**
 * Receives an HTTP request using SSL_read.
 * Adapted from: https://stackoverflow.com/questions/38714363/read-html-response-using-ssl-read-in-c-http-1-0
 */
char* receive_ssl_response(SSL *ssl) {
	int header_size = 1000;
	char *header = (char*) malloc(header_size * sizeof(char));
	if (header == NULL) {
		return NULL;
	}
	int body_size = 10000;
	char *body = (char*) malloc(body_size * sizeof(char));
	if (body == NULL) {
		return NULL;
	}
	int bytes;
	int received = 0;
	int i, line_length;
	char c[1];

	memset(header, '\0', header_size);
	memset(body, '\0', body_size);

	i = 0;
	line_length = 0;
	do {
		bytes = SSL_read(ssl, c, 1);
		if (bytes <= 0)
			break;
		if (c[0] == '\n') {
			if (line_length == 0)
				break;
			else
				line_length = 0;
		} else
			line_length++;
		if (i < header_size)
			header[i++] = c[0];
		received += bytes;
	} while (1);
	if (!strstr(header, "200 Success")) {
		return NULL;
	}
	free(header);

	char *buf = malloc(1024 * sizeof(char));
	received = 0;
	do {
		memset(buf, '\0', 1024 * sizeof(char));
		bytes = SSL_read(ssl, buf, 1024);
		if (bytes <= 0)
			break;
		if (body_size <= bytes + received) {
			body = realloc(body, 2 * body_size);
			body_size *= 2;
			if (!body) {
				free(body);
				return NULL;
			}
		}
		strcat(body, buf);
		received += bytes;
	} while (1);
	free(buf);
	return body;
}

/**
 * Parses certificates body into individual certificates
 */
CertificatesHandler* parse_certificates(char *body) {
	CertificatesHandler *certificates_handler;

	if (!(certificates_handler = (CertificatesHandler*) malloc(
			sizeof(CertificatesHandler)))) {
		fprintf(stderr, "Could not create certificates handler for request.\n");
		return NULL;
	}
	certificates_handler->num = 0;

	// get first line of message
	char *line = strtok(body, "\n");
	if (line == NULL) {
		return NULL;
	}
	int num_certs = atoi(line);
	if (num_certs <= 0) {
		free_certificates_handler(certificates_handler);
		return NULL;
	}
	certificates_handler->num = num_certs;
	certificates_handler->certificates = (char**) malloc((num_certs) * sizeof(char*));
	certificates_handler->recipients = (char**) malloc((num_certs) * sizeof(char*));
	int j = 0;
	while (j < num_certs) {
		// next line should be the recipient name
		line = strtok(NULL, "\n");
		if (line == NULL) {
			fprintf(stderr, "could not return recipient for certificate %d", j);
			free_certificates_handler(certificates_handler);
			return NULL;
		}
		certificates_handler->recipients[j] = malloc((strlen(line) + 1) * sizeof(char));
		strcpy(certificates_handler->recipients[j], line);

		// followed by the certificate
		line = strtok(NULL, "\n\nENDCERT\n\n");
		if (line == NULL) {
			fprintf(stderr, "could not return certificate for certificate %d", j);
			free_certificates_handler(certificates_handler);
			return NULL;
		}
		certificates_handler->certificates[j] = malloc((strlen(line) + 1) * sizeof(char));
		strcpy(certificates_handler->certificates[j], line);
		j++;
	}
	line = strtok(NULL, "");

	// should be nothing left over at end
	if (strlen(line) != 0) {
		fprintf(stderr, "certificates has leftover %s", line);
		free_certificates_handler(certificates_handler);
		return NULL;
	}
	return certificates_handler;
}

void free_certificates_handler(CertificatesHandler *certificates_handler) {
	if (certificates_handler == NULL) {
		return;
	}
	for (int j = 0; j < certificates_handler->num; j++) {
		free(certificates_handler->certificates[j]);
		free(certificates_handler->recipients[j]);
	}
	free(certificates_handler->certificates);
	free(certificates_handler->recipients);
	free(certificates_handler);
}
