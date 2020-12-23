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
#include <pwd.h>
#include <dirent.h>

#include <sys/time.h>

#include "create_ctx.h"
#include "user_io.h"
#include "custom_utils.h"
#include "request_handler.h"

#define h_addr h_addr_list[0] /* for backward compatibility */
#define TRUSTED_CA "trusted_ca/ca-chain.cert.pem"
#define SERVER_PORT 8081
#define CERT_LOCATION_TEMPLATE "mailboxes/%s/%s.cert.pem"
#define PRIVATE_KEY_TEMPLATE "mailboxes/%s/%s.private.key"
#define ENCRYPTED_MSG_TEMPLATE "mailboxes/%s/tmp_encrypted_msg.txt"
#define SIGNED_MSG_TEMPLATE "mailboxes/%s/tmp_signed_msg.txt"
#define RECIPIENT_CERT_TEMPLATE "mailboxes/%s/tmp_%s.cert.pem"
#define MAX_MAIL_SIZE 5000

int tcp_connection(char *host_name, int port);
void print_usage_information();
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
	char *username;
	struct passwd *pass; 
	pass = getpwuid(getuid()); 
	username = pass->pw_name;
	if (!username) {
		printf("Failed to determine identify of user.\n");
		exit(1);
 	}

	char certificate_path[256];
	char private_key_path[256];
	sprintf(certificate_path, CERT_LOCATION_TEMPLATE, username, username);
	sprintf(private_key_path, PRIVATE_KEY_TEMPLATE, username, username);

	if (!(ctx = create_ctx_client(certificate_path, private_key_path, TRUSTED_CA, 1))) {
		fprintf(stderr, "Please make sure that you have a private key and certificate "
				"before continuing. You can generate it using the 'getcert' program.\n");
		exit(2);
	}

	int MAX_RCPTS_LENGTH = 200;
	int MAX_PATH_LENGTH = 50;

	char path[MAX_PATH_LENGTH];
	char rcpts[MAX_RCPTS_LENGTH];

	if (get_sendmsg_args(argc, argv, path, rcpts, MAX_PATH_LENGTH, 
			MAX_RCPTS_LENGTH, MAX_RCPTS_LENGTH) < 0) {
		print_usage_information();
		exit(1);
	}
	
	// -------- Make sure file can be read and is valid size -------- //

	FILE* fp;
	if (!(fp = fopen(path, "r"))) {
		fprintf(stderr, "Sorry, the file your provided could not be opened. "
			"Did you provide the file path correctly?\n");
		exit(1);
	}
	fseek(fp, 0L, SEEK_END);     // go to the end of the file
	int n_bytes = ftell(fp);     // get the number of bytes
	fseek(fp, 0L, SEEK_SET);     // reset to beginning of file

	if (n_bytes > MAX_MAIL_SIZE) {
		fprintf(stderr, "The file you submitted exceeds the maximum allowed size.\n");
		exit(2);
	}
	fclose(fp);

	// -------  create the TCP socket ------- //

	if ((sock = tcp_connection("localhost", SERVER_PORT)) < 0) {
		fprintf(stdout, "Could not create TCP socket...\n");
		return 2;
	}

	// set socket timeout
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) != 0) {
		fprintf(stdout, "Error setting timeout\n");
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

	printf("This is the buffer sent to the server:\n%s\n", obuf);
	printf("These are the recipients: %s\n", rcpts);

	SSL_write(ssl, obuf, strlen(obuf));

	// --------- Get server response ---------- //

	RequestHandler* request_handler = NULL;
	CertificatesHandler *certs_handler = NULL;

	request_handler = parse_ssl_response(ssl);
	if (!request_handler) {
		fprintf(stdout, "Did not receive valid response from GET /certificates");
		goto CLEANUP;
	} else if (request_handler->command != SuccessResponse) {
		fprintf(stdout, "Did not receive successful response from GET /certificates");
		free_request_handler(request_handler);
		goto CLEANUP;
	}

	printf("Received recipient certificates!\n");
	certs_handler = parse_certificates(request_handler->request_content);
	if (!certs_handler) {
		printf("Could not parse certificates in response message received from server.\n");
		free_request_handler(request_handler);
		goto CLEANUP;
	} 

	printf("Successfully parsed certificates!\n");
	if (certs_handler->num == 0) {
		printf("No valid recipients found.\n");
	}
	else {
		FILE *tmpfile;
		char path_buf[100];
		for (int i = 0; i < certs_handler->num; i++) {
			memset(path_buf, '\0', sizeof(path_buf));

			if (certs_handler->certificates[i] == NULL)
				continue;
				
			printf("Attempting to write certificate to file...\n");
			snprintf(path_buf, sizeof(path_buf), RECIPIENT_CERT_TEMPLATE,
					username, certs_handler->recipients[i]);

			tmpfile = fopen(path_buf, "wb+");
			fwrite(certs_handler->certificates[i], sizeof(char),
					strlen(certs_handler->certificates[i]), tmpfile);
			fclose(tmpfile);
		}
	}
	// ------ Encrypt messages and send them to the server----- //

	printf("Encrypting messages to send to server...\n");

	for (int i = 0; i < certs_handler->num; i++) {
		if (certs_handler->certificates[i] == NULL) {
			printf("Did not receive certificate for recipient, so cannot send encrypted "
					"message to their mailbox '%s'\n", certs_handler->recipients[i]);
			continue;
		}
		
		char encrypt_msg_path_buf[128];
		sprintf(encrypt_msg_path_buf, ENCRYPTED_MSG_TEMPLATE, username);

		char rcpt_cert_buf[128];
		snprintf(rcpt_cert_buf, sizeof(rcpt_cert_buf), RECIPIENT_CERT_TEMPLATE,
				username, certs_handler->recipients[i]);

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
			fprintf(stderr,"Could not open digitally signed and encrypted message file\n");
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
		// POST /sendmsg HTTP/1.0
		// Content-Length: X
		//
		// sender 
		// recipient
		char header_buf[256];
		char content_buf[256 + n_bytes];
		int body_len = strlen(certs_handler->recipients[i]) + strlen(username) 
			+ strlen(file_buf) + 2;

		sprintf(header_buf, "POST /sendmsg HTTP/1.0\nContent-Length: %d\n\n", body_len);
		sprintf(content_buf, "%s\n%s\n%s", username, certs_handler->recipients[i], file_buf);

		SSL_write(ssl, header_buf, strlen(header_buf));
		SSL_write(ssl, content_buf, strlen(content_buf));

		// --------- Get server response to request to sendmsg ---------- //

		char response_buf[4096];
		err = SSL_read(ssl, response_buf, sizeof(response_buf) - 1);
		response_buf[err] = '\0';

		if (strstr(response_buf, "200 Success")) {
			fprintf(stdout, "Your message was successfully mailed "
					"to %s.\n", certs_handler->recipients[i]);
		} else {
			printf("Server unsuccessful response:\n%s\n", response_buf);
			printf("Sorry, an error occurred in sending your message "
					"to %s.\n", certs_handler->recipients[i]);
		}
	}
	char end_buf[4096];
	sprintf(end_buf, "POST /sendmsg HTTP/1.0\nContent-Length: %d\n\n", 0);
	SSL_write(ssl, end_buf, strlen(end_buf) + 1);

	// ------- Clean Up -------- //
	CLEANUP:
	remove_temporary_files_from_mailbox(username);
	free_certificates_handler(certs_handler);
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
	if (!(in = BIO_new_file(encrypted_msg_path, "r"))) {
		fprintf(stderr, "Could not open content to be digitally signed\n");
		goto err;
	}

	/* Sign content */
	if (!(cms = CMS_sign(scert, skey, NULL, in, flags))) {
		fprintf(stderr, "Could not sign message content\n");
		goto err;
	}

	if (!(out = BIO_new_file(signed_msg_path, "w"))) {
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
	if (!(tbio = BIO_new_file(rcpt_cert_path, "rb+"))) {
		fprintf(stderr, "Could not open recipient certificate at %s\n",
				rcpt_cert_path);
		goto err;
	}

	if (!(rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL))) {
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
	if (!(in = BIO_new_file(msg_path, "r"))) {
		fprintf(stderr, "Could not open message content to be encrypted.\n");
		goto err;
	}

	/* encrypt content */
	if (!(cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags))) {
		fprintf(stderr, "Could not encrypt content to CMS\n");
		goto err;
	}

	if (!(out = BIO_new_file(encrypted_msg_path, "w"))) {
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
					"* [-r] a list of recipient usernames for the message (maximum 10)\n"
					"Example usage: sendmsg -f ./test.txt -r recpt1 recpt2 recpt3\n\n");
}

/**
 * Parses certificates body into individual certificates
 */
CertificatesHandler* parse_certificates(char *body) {
	CertificatesHandler *certificates_handler;

	if (!(certificates_handler = (CertificatesHandler*) malloc(sizeof(CertificatesHandler)))) {
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
			fprintf(stderr, "Could not return recipient for certificate %d", j);
			free_certificates_handler(certificates_handler);
			return NULL;
		}

		// save name of the recipient
		certificates_handler->recipients[j] = malloc((strlen(line) + 1) * sizeof(char));
		strcpy(certificates_handler->recipients[j], line);

		// ----------- Save the content of the corresponding cert --------
		int cert_buf_size = 4096;
		char cert_buf[cert_buf_size];
		int cert_len = 0;
		char *start_cert = "-----BEGIN CERTIFICATE-----";
		char *end_cert= "-----END CERTIFICATE-----";
		char *no_cert = "NOCERT";

		line = strtok(NULL, "\n");
		if (!strcmp(line, start_cert)) {
			memcpy(&cert_buf[cert_len], start_cert, strlen(start_cert));
			cert_buf[strlen(start_cert)] = '\n';
			cert_len += (strlen(start_cert) + 1);

		} else if (!strcmp(line, no_cert)) {
			fprintf(stdout, "No certificate is available for %s recipient..\n",
					certificates_handler->recipients[j]);
			certificates_handler->certificates[j] = NULL;
			line = strtok(NULL, "\n");
			continue;

		} else {
			fprintf(stderr, "Certificate appears to be missing or in incorrect location.\n");
			free_certificates_handler(certificates_handler);
			return NULL;
		}

		while ((line = strtok(NULL, "\n")) && strcmp(line, end_cert) && cert_len < cert_buf_size) {
			memcpy(&cert_buf[cert_len], line, strlen(line));
			cert_buf[cert_len + strlen(line)] = '\n';
			cert_len += (strlen(line) + 1);
		}

		if (strcmp(line, end_cert)) {
			// we never found the end of the certificate, sigh...
			fprintf(stderr, "Certificate contains unexpected content.\n");
			free_certificates_handler(certificates_handler);
		} else {
			memcpy(&cert_buf[cert_len], end_cert, strlen(end_cert));
			cert_buf[cert_len + strlen(end_cert)] = '\n';
			cert_len += (strlen(end_cert) + 1);
		}
		cert_buf[cert_len] = '\0';

		if (!strlen(cert_buf)) {
			fprintf(stderr, "Could not return certificate for certificate %d", j);
			free_certificates_handler(certificates_handler);
			return NULL;
		}
		certificates_handler->certificates[j] = malloc((strlen(cert_buf) + 1) * sizeof(char));
		strcpy(certificates_handler->certificates[j], cert_buf);
		j++;
	}

	// there should be a trailing \n and that's it
	line = strtok(NULL, "");
	if (strlen(line) == 0 || !(strlen(line) == 1 && line[0] == '\n')) {
		fprintf(stderr, "The certificates has unexpected leftover content of len (%lu):\n'%s'\n", strlen(line), line);
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
