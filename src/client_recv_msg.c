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
#include <openssl/cms.h>
#include <openssl/x509.h>
#include <pwd.h>

#include "create_ctx.h"
#include "user_io.h"
#include "custom_utils.h"

#define h_addr h_addr_list[0]  /* for backward compatibility */
#define TRUSTED_CA "trusted_ca/ca-chain.cert.pem"
#define CERT_LOCATION_TEMPLATE "mailboxes/%s/%s.cert.pem"
#define PRIVATE_KEY_TEMPLATE "mailboxes/%s/%s.private.key"
#define SENDER_CERT_TEMPLATE "mailboxes/%s/tmp_%s.cert.pem"
#define ENCRYPTED_MSG_TEMPLATE "mailboxes/%s/tmp_encrypted_msg.txt"
#define VERIFIED_ENCRYPTED_MSG_TEMPLATE "mailboxes/%s/tmp_verified_msg.txt"
#define DECRYPTED_MSG_TEMPLATE "mailboxes/%s/tmp_decrypted_msg.txt"
#define SERVER_PORT 8081

int tcp_connection(char *host_name, int port);
int verify_message(char *msg_file_path, char *verified_msg_path,
		char *sender_cert_path);
int decrypt_message(char *encrypted_msg_path, char *decrypted_msg_path,
		char *client_cert_path, char *client_pkey_path);


int main(int argc, char **argv) {
	int err;
	char *s;
	SSL_CTX *ctx;
	int sock;

	if (argc > 1) {
		fprintf(stderr, "Unexpected arguments received. No arguments are required "
			"for this program.\nExample usage of this program:\n$ ./bin/recvmsg\n");
		exit(1);
	}

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

	// -------- Make request to get a message from server -------- //

	char obuf[4096];
	sprintf(obuf, "GET /message HTTP/1.0\nContent-Length: %lu\n\n%s",
			strlen(username), username);
	SSL_write(ssl, obuf, strlen(obuf));

	// -------- Get server response and parse the content---------//

	char response_buf[4096];
	char msg_file_path[256];
	char sender_cert_path[256];
	err = SSL_read(ssl, response_buf, sizeof(response_buf) - 1);
	response_buf[err] = '\0';

	if (strstr(response_buf, "200 Success")) {
		
		// find the content length returned
		char *line = NULL;
		char *content_ptr = NULL;
		int content_length = 0;

		line = strtok(response_buf, "\n"); 
		if (!(line = strtok(NULL, "\n")) 
				|| !(content_ptr = strchr(line, ':'))) {
			fprintf(stderr, "Server returned unexpected content. "
				"Your message cannot be delivered\n");
			goto CLEANUP;
		}

		content_length = atoi(content_ptr + 1);
		if (content_length == 0) {
			fprintf(stdout, "You have no unread messages at this time.\n");
			goto CLEANUP;
		}

		// ----- Parse Sender Information from Request Body ------ //

		char *remaining_content;
		if (!(remaining_content = strtok(NULL, ""))
				|| strlen(remaining_content) < 2
				|| remaining_content[0] != '\n') {
			fprintf(stderr, "Server returned unexpected content. "
					"Your message cannot be delivered\n");
			goto CLEANUP;
		}

		// rest of the content should be the sender name; ignore the \n character
		char *sender_name = &remaining_content[1];
		printf("Received new message from %s!\n", sender_name);

		// ---------- Read in the sender certificate ------- //

		char content_buf[content_length];
		err = SSL_read(ssl, content_buf, sizeof(content_buf) - 1);
		content_buf[err] = '\0';

		// save certificate to a local tmp file
		snprintf(sender_cert_path, sizeof(sender_cert_path),
				SENDER_CERT_TEMPLATE, username, sender_name);
		if (!save_content_to_file(content_buf, sender_cert_path)) {
			fprintf(stderr, "Failed to write sender certificate to file\n");
			goto CLEANUP;
		}

		// ---------- Read in the message content ------- //

		memset(content_buf, 0, content_length);
		err = SSL_read(ssl, content_buf, sizeof(content_buf) - 1);
		content_buf[err] = '\0';

		// save the encrypted content to a local tmp file
		sprintf(msg_file_path, ENCRYPTED_MSG_TEMPLATE, username);
		if (!save_content_to_file(content_buf, msg_file_path)) {
			fprintf(stderr, "Failed to save encrypted, signed content to file\n");
			goto CLEANUP;
		}
		
	} else {
		printf("Sorry, the server couldn't send back any messages at this time.\n");
		goto CLEANUP;
	}

	// ---- Verify and decrypt the content that the server returned --- //

	char verified_msg_path_buf[128];
	sprintf(verified_msg_path_buf, VERIFIED_ENCRYPTED_MSG_TEMPLATE, username);

	char decrypted_msg_path_buf[128];
	sprintf(decrypted_msg_path_buf, DECRYPTED_MSG_TEMPLATE, username);

	// Verify the digitally signed message against the sender's certificate
	if (!verify_message(msg_file_path, verified_msg_path_buf, sender_cert_path)) {
		fprintf(stdout, "Message could not be verified from the sender. Sorry!\n");
		goto CLEANUP;
	}

	// Decrypt the message using client's private key
	if (!decrypt_message(verified_msg_path_buf, decrypted_msg_path_buf, 
			certificate_path, private_key_path)) {
		fprintf(stdout, "Message from server could not be decrypted. Sorry!\n");
		goto CLEANUP;
	}

	// ------- Print out message contents for the user ------ //
	FILE *fp = fopen(decrypted_msg_path_buf, "r");
	if (!fp) {
		fprintf(stderr, "Could not reopen decrypted file to provide content.\n");
	}

	fprintf(stdout, "Here are the contents of your message:\n");
	fprintf(stdout, "--------------------------------------\n");
	char ch;
	while ((ch = fgetc(fp)) != EOF) {
		fprintf(stdout, "%c", ch);
	}
	fclose(fp);
	fprintf(stdout, "--------------------------------------\n");

	// ------- Clean Up Everything -------- //
CLEANUP:
	remove_temporary_files_from_mailbox(username);
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
		fprintf(stdout, "Socket creation failed.\n");
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
 * Verifies that a message has been sent from the intended sender
 * by checking the public key of the sender against the digitally signed
 * file content. Sender certificate must be saved to a file identified by sender_cert_path.
 * 
 * The verified content will be saved to a file at verified_msg_path.
 * Returns 0 if succesful, 1 if error
 * 
 * Source code derived from openssl demos files provided for project
 */
int verify_message(char *msg_file_path, char *verified_msg_path, 
		char *sender_cert_path) {

    BIO *in = NULL, *out = NULL, *sender = NULL, *tbio = NULL, *cont = NULL, *tbio_inter = NULL;
    X509_STORE *st = NULL;
    X509 *root_ca_cert = NULL;
	X509 *intermediate_ca_cert = NULL;
	X509 *sender_cert = NULL;
	STACK_OF(X509) *sender_stack = NULL;
    CMS_ContentInfo *cms = NULL;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
	int success = 0;

    // ------ Set up trusted CA certificate store ------ //
	st = X509_STORE_new(); // hold trusted CA certs in CA store
	
	// --- Push root ca to trusted stack

    if (!(tbio = BIO_new_file("trusted_ca/root.cert.pem", "r"))) {
		fprintf(stderr, "Could open file containg root CA certificate\n");
        goto CLEANUP;
	}
    
    if (!(root_ca_cert = PEM_read_bio_X509(tbio, NULL, 0, NULL))) {
		fprintf(stderr, "Could not read X509 cert from root CA certificate\n");
        goto CLEANUP;
	}
    if (!X509_STORE_add_cert(st, root_ca_cert)) {
		fprintf(stderr, "Could not add root certificate to trusted CA store\n");
        goto CLEANUP;
	}

	// --- Push intermediate ca to trusted stack

    if (!(tbio_inter = BIO_new_file("trusted_ca/intermediate.cert.pem", "r"))) {
		fprintf(stderr, "Could not open file containing intermediate CA certificate\n");
        goto CLEANUP;
	}
    
    if (!(intermediate_ca_cert = PEM_read_bio_X509(tbio_inter, NULL, 0, NULL))) {
		fprintf(stderr, "Could not read X509 cert from intermediate CA certificate\n");
        goto CLEANUP;
	}
    if (!X509_STORE_add_cert(st, intermediate_ca_cert)) {
		fprintf(stderr, "Could not add intermediate certificate to trusted CA store\n");
        goto CLEANUP;
	}

	// ------ Read in sender's certificate and save to STACK_OF(X509) ------ //

	if (!(sender = BIO_new_file(sender_cert_path, "rb+"))) {
		fprintf(stderr, "Could not open sender certificate at %s\n",
				sender_cert_path);
		goto CLEANUP;
	}

	if (!(sender_cert = PEM_read_bio_X509(sender, NULL, 0, NULL))) {
		fprintf(stderr, "Could not read recipient X509 from sender certificate\n");
		goto CLEANUP;
	}

	/* Create sender STACK and add sender cert to it */
	sender_stack = sk_X509_new_null();
	if (!sender_stack || !sk_X509_push(sender_stack, sender_cert)) {
		fprintf(stderr, "Could not add sender cert to certificate stack\n");
		goto CLEANUP;
	}
	
	// sk_X509_pop_free will free up recipient STACK and its contents so set
	// sender_cert to NULL so it isn't freed up twice.
	sender_cert = NULL;

    // ------------ Open message being verified ----------- //

    if (!(in = BIO_new_file(msg_file_path, "r"))) {
		fprintf(stderr, "Could not read in file content to be decrypted.\n");
        goto CLEANUP;
	}

    if (!(cms = SMIME_read_CMS(in, &cont))) {
		fprintf(stderr, "Could not parse message from CMS\n");
        goto CLEANUP;
	}

	// File to output verified content to */
    if (!(out = BIO_new_file(verified_msg_path, "w"))) {
		fprintf(stderr, "Could not open new file to save verified content to.\n");
		goto CLEANUP;
	}

	// These settings say: "Please verify the CMS structure against a set of certificates
	// that are currently in the certificate stack, sender_stack against the known and trusted
	// cas that I have provided to the trusted CA list, st."
    if (!CMS_verify(cms, sender_stack, st, cont, out, CMS_NOINTERN)) {
        fprintf(stderr, "Verification of Sender Failed\n");
        goto CLEANUP;
    }
    success = 1;

 CLEANUP:
    if (!success) {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
	X509_free(sender_cert);
	sk_X509_pop_free(sender_stack, X509_free);
    X509_free(root_ca_cert);
	X509_free(intermediate_ca_cert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
	BIO_free(tbio_inter);
	BIO_free(sender);
    return success;
}
/**
 * Decrypts an encrypted message using the client's private key located
 * at client_pkey_path and the client's public key located at client_cert_path.
 * 
 * Function returns 0 on success and 1 on failure
 * Source code derived from openssl demos files provided for project
 */
int decrypt_message(char *encrypted_msg_path, char *decrypted_msg_path, 
		char *client_cert_path, char *client_pkey_path) {
    
	BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int success = 0;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // ------ Read in recipient (client) certificate and private key --- //
    if (!(tbio = BIO_new_file(client_cert_path, "r"))) {
		fprintf(stderr, "Could not access client certificate file\n");
        goto CLEANUP;
	}

	if (!(rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL))) {
		fprintf(stderr, "Could not read in the client's X509 certificate key");
        goto CLEANUP;
	}

	// not sure how the private key gets read from BIO in the provided example
	// so reading the private key separately
	// skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
	FILE *fp = fopen(client_pkey_path, "rb+");
	if (!fp || !(rkey = PEM_read_PrivateKey(fp, NULL, 0, NULL))) {
		fprintf(stderr, "Could not read in private key contents\n");
		goto CLEANUP;
	}
	fclose(fp);

    // ----- Open the content to decrypt and do the decryption ----//
    if (!(in = BIO_new_file(encrypted_msg_path, "r"))) {
		fprintf(stderr, "Could not read in encrypted file content\n");
        goto CLEANUP;
	}

    if (!(cms = SMIME_read_CMS(in, NULL))) {
        fprintf(stderr, "Could not parse encrypted content from file\n");
		goto CLEANUP;
	}

    if (!(out = BIO_new_file(decrypted_msg_path, "w"))) {
        fprintf(stderr, "Could not open/create decrypted message content file\n");
		goto CLEANUP;
	}

    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0)) {
		fprintf(stderr, "Error occurred while decrypting S/MIME message\n");
        goto CLEANUP;
	}
    success = 1;

 CLEANUP:

    if (!success) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return success;
}
