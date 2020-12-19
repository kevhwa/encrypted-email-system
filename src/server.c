#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>  
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <ctype.h>
#include <dirent.h>
#include <crypt.h>  // needs to be included if using linux machine

#include "user_io.h"
#include "create_ctx.h"
#include "server.h"

#define SERVER_PORT 8080
#define ON  1
#define OFF 0
#define BAD_REQUEST 400
#define NOT_FOUND 404
#define CERTIFICATE_FILE "ca/certs/ca-chain.cert.pem"
#define TRUSTED_CA_FILE "ca/certs/intermediate.cert.pem"
#define PRIVATE_KEY_FILE "ca/private/intermediate.key.pem"

const char *bad_request_resp = "HTTP/1.0 400 Bad Request\nContent-Length: 0\n\n";
const char *not_found_resp = "HTTP/1.0 404 Not Found\nContent-Length: 0\n\n";
const char *unauthorized_resp = "HTTP/1.0 401 Unauthorized\nContent-Length: 0\n\n";
const char *conflict_resp = "HTTP/1.0 409 Conflict\nContent-Length: %d\n\n";
const char *internal_error_resp = "HTTP/1.0 500 Internal Server Error\nContent-Length: 0\n\n";
const char *success_template = "HTTP/1.0 200 Success\nContent-Length: %d\n\n";

int tcp_listen();
RequestHandler* init_request_handler();
void free_request_handler(RequestHandler *request_handler);
int check_credential(char *username, char *submitted_password);
int parse_credentials_from_request_body(char *request_body, char uname[],
		char pwd[], int buf_len);
int generate_cert(X509_REQ *req, const char *p_ca_path,
		const char *p_ca_key_path, const char *uname);
X509_REQ* read_x509_req_from_file(char *path);
int write_x509_req_to_file(char *csr, char *path);
int write_x509_cert_to_file(X509 *cert, char *path);
int read_x509_cert_from_file(char *cert_buf, int size, char *path);
int rand_serial(ASN1_INTEGER *ai);
int write_new_password(char *pass, char *path);
int awaiting_messages_for_client(char *path);

int main(int argc, char **argv) {
	int err;
	BIO *sbio;
	SSL *ssl;
	char *s;
	SSL_CTX *ctx;
	int sock, rqst;

	// create the SSL context, with option to use authentication

	if (argc > 1 && argv[1] == "-a")
		ctx = create_ctx_server(CERTIFICATE_FILE, PRIVATE_KEY_FILE, TRUSTED_CA_FILE, ON);
	else
		ctx = create_ctx_server(CERTIFICATE_FILE, PRIVATE_KEY_FILE, NULL, OFF);

	// create the TCP socket
	if ((sock = tcp_listen()) < 0) {
		return 2;
	}
	fprintf(stdout, "\nServer started!\n");

	for (;;) {
		struct sockaddr_in client_addr;
		socklen_t alen = sizeof(client_addr);

		fprintf(stdout, "\nWaiting for connection...\n\n");
		rqst = accept(sock, (struct sockaddr*) &client_addr, &alen);
		if (rqst < 0) {
			fprintf(stderr, "Unable to accept connection.\n");
		}
		fprintf(stdout, "Connection from %x, port %x\n",
				client_addr.sin_addr.s_addr, client_addr.sin_port);

		sbio = BIO_new_socket(rqst, BIO_NOCLOSE);
		ssl = SSL_new(ctx);
		SSL_set_bio(ssl, sbio, sbio);
		err = SSL_accept(ssl);

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

		char buf[4096];
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		buf[err] = '\0';
		fprintf(stdout, "Received %d chars of content:\n---\n%s----\n", err,
				buf);

		// --- Validate request and send resp back to the SSL client ---
		int max_auth_len = 20;
		char uname_buf[max_auth_len];
		char pwd_buf[max_auth_len];
		RequestHandler *request_handler = handle_recvd_msg(buf);

		if (!request_handler) {
			err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
			goto CLEANUP;
		} else if (request_handler->status_code == BAD_REQUEST) {
			err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
			goto CLEANUP;
		} else if (request_handler->status_code == NOT_FOUND) {
			err = SSL_write(ssl, not_found_resp, strlen(not_found_resp));
			goto CLEANUP;
		}

		if (parse_credentials_from_request_body(
				request_handler->request_content, uname_buf, pwd_buf,
				max_auth_len) < 0) {
			err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
			goto CLEANUP;
		}

		if (!check_credential(uname_buf, pwd_buf)) {
			printf("Authentication failed.\n");
			err = SSL_write(ssl, unauthorized_resp, strlen(unauthorized_resp));
			goto CLEANUP;
		}
		
		memset(buf, 0, sizeof(buf));
		if (request_handler->command == ChangePW) {
			SSL_read(ssl, buf, sizeof(buf) - 1);
			if (strlen(buf) < 2) {
				err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
				goto CLEANUP;
			}
		}

		//--- If there are unread messages for client, don't let them change their certificate --- //
		char path[100];
		snprintf(path, sizeof(path), "mailboxes/%s", uname_buf);
		if ((err = awaiting_messages_for_client(path)) != 0) {
			if (err < 0) {
				fprintf(stderr, "Error occurred trying to determine unread messages.\n");
				err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
				goto CLEANUP;
			} else {
				fprintf(stdout, "Client has unread messages; will not change certificate.\n");
				err = SSL_write(ssl, conflict_resp, strlen(conflict_resp));
				goto CLEANUP;
			}
		}

		// --- Passed authentication and OK to change cert. Read in certificate request --- //
		char cert_buf[4096];
		int temp = SSL_read(ssl, cert_buf, sizeof(cert_buf) - 1);
		cert_buf[temp] = '\0';

		// ------------ Save CSR to a CSR file   ----- //
		memset(path, 0, sizeof(path));
		X509_REQ *x509_req;
		snprintf(path, sizeof(path), "mailboxes/%s/%s.csr.pem",
				uname_buf, uname_buf);

		if (!write_x509_req_to_file(cert_buf, path)) {
			printf("failed to write csr to file");
			goto CLEANUP;
		}

		// ----- Read in the CSR as a CSR object ----- //
		if (!(x509_req = read_x509_req_from_file( path))) {
			printf("failed to read csr from file");
			goto CLEANUP;
		}

		int res = generate_cert(x509_req, CERTIFICATE_FILE, PRIVATE_KEY_FILE, uname_buf);
		if (res <= 0) {
			err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
			printf("error within generate cert\n");
			goto CLEANUP;
		}

		// --- Read certificate and send to user ---//
		char read_certbuf[4096];
		char tmp_buf[100];
		int read_len = 0;
		snprintf(tmp_buf, sizeof(tmp_buf), "mailboxes/%s/%s.cert.pem", uname_buf, uname_buf);

		if ((read_len = read_x509_cert_from_file(read_certbuf,
				sizeof(read_certbuf), tmp_buf)) == 0) {

			err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
			goto CLEANUP;
		}

		// --- Write new password to file, if changepw --- //
		if (request_handler->command == ChangePW) {
			char path_buf[100];
			snprintf(path_buf, sizeof(path_buf), "passwords/%s.txt", uname_buf);

			if (!write_new_password(buf, path_buf)) {
				fprintf(stderr, "Error ocurred writing password");
				err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
				goto CLEANUP;
			}
		}
		
		char content_buf[4096];
		sprintf(content_buf, success_template, read_len);

		err = SSL_write(ssl, content_buf, strlen(content_buf));
		err = SSL_write(ssl, read_certbuf, read_len);

		CLEANUP: 
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(rqst);
		free_request_handler(request_handler);
	}
	close(sock);
	SSL_CTX_free(ctx);
}

/**
 * Writes new (salted and hashed) password to a user's password file.
 */
int write_new_password(char *pass, char *path) {

	// generate random bytes
	unsigned char random_salt[16];
	int err = RAND_bytes(random_salt, 16);
	if (err != 1) {
		return 0;
	}
	
	char *salt_values = "abcdefghijklmnopqrstuvwxzyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
	for (int i = 0; i < 16; i++) {
		unsigned char mask = 63;
		unsigned char masked = random_salt[i] & mask;
		random_salt[i] = salt_values[masked];
	}
	
	int pass_size = 20;	
	char salt_buf[pass_size];
	sprintf(salt_buf, "$6$%s", random_salt);
	salt_buf[19] = '\0';

	const char *salt_for_crypt = salt_buf;
	char *c = crypt((const char *) pass, salt_for_crypt);

	FILE *fp;
	if (!(fp = fopen(path, "wb+"))) {
		printf("Could not write new password to file\n");
		return 0;
	}
	fwrite(c, 1, strlen(c), fp);
	fclose(fp);

	return 1;
}

/**
 * Count the number of messages awaiting for client.
 */
int awaiting_messages_for_client(char *path) {
	int message_count = 0;
	DIR *dir;
	struct dirent *de;

	// These are files to ignore in the count
	char *parent = "..";
	char *current = ".";
	char *known_cert_ext = ".cert.pem";
	char *known_csr_ext = ".csr.pem";

	if (!(dir = opendir(path))) {
		fprintf(stderr, "Could not open directory of mailboxes "
				"to check for unread messages.\n");
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		// make sure it's not one of the other known files for
		// certificates and csr that may be stored in the server dir
		char *filename = de->d_name;
		int len = strlen(filename);

		if (!strcmp(parent, filename) || !strcmp(current, filename)) {
			continue;
		}
		else if (len >= strlen(known_csr_ext)
				&& strcmp(known_csr_ext, &filename[len - strlen(known_csr_ext)]) == 0) {
			continue;
		} else if (len >= strlen(known_cert_ext)
				&& strcmp(known_cert_ext, &filename[len - strlen(known_cert_ext)]) == 0) {
			continue;
		} else {
			message_count++;
		}
	}
	closedir(dir);
	printf("Client currently has %d unread messages on server.\n", message_count);
	return message_count;
}

/**
 * Setup a TCP socket for a connection. Returns file
 * descriptor for socket.
 */
int tcp_listen() {

	struct sockaddr_in sin;
	int sock;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("cannot create server socket");
		return -1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(SERVER_PORT);

	if (bind(sock, (struct sockaddr*) &sin, sizeof(sin)) < 0) {
		perror("bind server failed");
		return -1;
	}

	if (listen(sock, 5) < 0) {
		perror("listen failed");
		return -1;
	}

	return sock;
}

/**
 * Writes a X509 REQ to a file. REQ in form of char *, not X509_REQ.
 */
int write_x509_req_to_file(char *csr, char *path) {

	FILE *fp;
	if (!(fp = fopen(path, "wb+"))) {
		printf("Could not open file to write CSR\n");
		return 0;
	}
	fwrite(csr, 1, strlen(csr), fp);
	fclose(fp);

	return 1;
}

/**
 * Reads X509_REQ from a file containing the REQ.
 */
X509_REQ* read_x509_req_from_file(char *path) {

	FILE *fp;
	if (!(fp = fopen(path, "rb+"))) {
		printf("Could not open file to read CSR\n");
		return NULL;
	}
	X509_REQ *x509_req = PEM_read_X509_REQ(fp, NULL, 0, NULL);
	fclose(fp);

	return x509_req;
}

/**
 * Saves a X509 certificate to a file.
 */
int write_x509_cert_to_file(X509 *cert, char *path) {

	FILE *p_file = NULL;
	if (NULL == (p_file = fopen(path, "wb+"))) {
		printf("Failed to open file for saving csr\n");
		return 0;
	}

	PEM_write_X509(p_file, cert);
	fclose(p_file);
	return 1;
}

/**
 * Reads a X509 certificate from file into cert_buf 
 * (does not read in as a X509).
 */
int read_x509_cert_from_file(char *cert_buf, int size, char *path) {

	FILE *fp;
	if (!(fp = fopen(path, "rb+"))) {
		printf("Could not open file to read certificate\n");
		return 0;
	}

	int read = fread(cert_buf, 1, size, fp);
	fclose(fp);

	return read;
}

/**
 * Function sourced from OpenSSL demo by egorovandreyrm
 * at https://github.com/egorovandreyrm/openssl_cert_req/blob/master/main.cpp
 */
int rand_serial(ASN1_INTEGER *ai) {
	BIGNUM *p_bignum = NULL;
	int ret = -1;

	if (!(p_bignum = BN_new())) {
		goto CLEANUP;
	}

	if (!BN_pseudo_rand(p_bignum, 64, 0, 0)) {
		goto CLEANUP;
	}

	if (ai && !BN_to_ASN1_INTEGER(p_bignum, ai)) {
		goto CLEANUP;
	}
	ret = 1;

	CLEANUP: BN_free(p_bignum);
	return ret;
}

/**
 * Generates a X509 certificate for a user and saves the new
 * certificate to the server under the user.
 * 
 * Function sourced from OpenSSL demo by egorovandreyrm
 * at https://github.com/egorovandreyrm/openssl_cert_req/blob/master/main.cpp
 */
int generate_cert(X509_REQ *x509_req, const char *p_ca_path,
		const char *p_ca_key_path, const char *uname) {
	FILE *p_ca_file = NULL;
	X509 *p_ca_cert = NULL;
	EVP_PKEY *p_ca_pkey = NULL;
	FILE *p_ca_key_file = NULL;
	EVP_PKEY *p_ca_key_pkey = NULL;
	X509 *p_generated_cert = NULL;
	ASN1_INTEGER *p_serial_number = NULL;
	EVP_PKEY *p_cert_req_pkey = NULL;
	int success = 0;

	// ---- read-in CA information ----

	if ((p_ca_file = fopen(p_ca_path, "r")) == NULL) {
		printf("Failed to open the CA certificate file\n");
		goto CLEANUP;
	}

	if (!(p_ca_cert = PEM_read_X509(p_ca_file, NULL, 0, NULL))) {
		printf("Failed to read X509 CA certificate\n");
		goto CLEANUP;
	}

	if (!(p_ca_pkey = X509_get_pubkey(p_ca_cert))) {
		printf("Failed to get X509 CA pkey\n");
		goto CLEANUP;
	}

	if (!(p_ca_key_file = fopen(p_ca_key_path, "r"))) {
		printf("Failed to open the private key file\n");
		goto CLEANUP;
	}

	if (!(p_ca_key_pkey = PEM_read_PrivateKey(p_ca_key_file, NULL, NULL, NULL))) {
		printf("Failed to read the private key file\n");
		goto CLEANUP;
	}

	// ---- Create a new X509 certificate ----

	if (!(p_generated_cert = X509_new())) {
		printf("Failed to allocate a new X509\n");
		goto CLEANUP;
	}

	// set information on new certificate 
	p_serial_number = ASN1_INTEGER_new();
	rand_serial(p_serial_number);
	X509_set_serialNumber(p_generated_cert, p_serial_number);

	X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert));
	X509_set_subject_name(p_generated_cert,
			X509_REQ_get_subject_name(x509_req));

	X509_gmtime_adj(X509_get_notBefore(p_generated_cert), 0L);
	X509_gmtime_adj(X509_get_notAfter(p_generated_cert), 31536000L);

	if (!(p_cert_req_pkey = X509_REQ_get_pubkey(x509_req))) {
		printf("Failed to get public key from certificate\n");
		X509_free(p_generated_cert);
		p_generated_cert = NULL;
		goto CLEANUP;
	}

	if (X509_set_pubkey(p_generated_cert, p_cert_req_pkey) < 0) {
		printf("Failed to set public key to new certificate\n");
		X509_free(p_generated_cert);
		p_generated_cert = NULL;
		goto CLEANUP;
	}

	if (EVP_PKEY_copy_parameters(p_ca_pkey, p_ca_key_pkey) < 0) {
		printf("Failed to copy parameters\n");
		X509_free(p_generated_cert);
		p_generated_cert = NULL;
		goto CLEANUP;
	}

	if (X509_sign(p_generated_cert, p_ca_key_pkey, EVP_sha256()) < 0) {
		printf("Failed to sign the certificate\n");
		X509_free(p_generated_cert);
		p_generated_cert = NULL;
		goto CLEANUP;
	}

	// ---- Save X509 certificate as a file on the server ----

	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "mailboxes/%s/%s.cert.pem",
			uname, uname);
	if (write_x509_cert_to_file(p_generated_cert, path_buf)) {
		success = 1;
	}

	CLEANUP: fclose(p_ca_file);
	X509_free(p_ca_cert);
	EVP_PKEY_free(p_ca_pkey);
	fclose(p_ca_key_file);
	EVP_PKEY_free(p_ca_key_pkey);
	ASN1_INTEGER_free(p_serial_number);
	EVP_PKEY_free(p_cert_req_pkey);
	X509_free(p_generated_cert);

	return success;
}


/**
 * Extracts the command and content from an incoming request
 * into a RequestHandler struct.
 */
RequestHandler* handle_recvd_msg(char *buf) {

	char *getcert = "POST /getcert HTTP/1.0";
	char *changepw = "POST /changepw HTTP/1.0";
	char *sendmsg = "POST /sendmsg HTTP/1.0";
	char *recvmsg = "POST /recvmsg HTTP/1.0";

	RequestHandler *request_handler = init_request_handler();
	if (!request_handler) {
		fprintf(stderr, "Could not handle received message.\n");
		return NULL;
	}

	char buf_cpy[strlen(buf) + 1];
	strcpy(buf_cpy, buf);
	buf_cpy[strlen(buf)] = '\0';

	// get first line of message
	char *line = strtok(buf_cpy, "\n");
	if (line == NULL) {
		request_handler->status_code = BAD_REQUEST;
		return request_handler;
	}

	// http version can be anything; just make sure that the rest matches
	if ((strncmp(getcert, line, strlen(getcert) - 3) == 0)
			&& (strlen(line) == strlen(getcert))) {
		request_handler->command = GetCert;
	} else if ((strncmp(changepw, line, strlen(changepw) - 3) == 0)
			&& (strlen(line) == strlen(changepw))) {
		request_handler->command = ChangePW;
	} else if ((strncmp(changepw, line, strlen(sendmsg) - 3) == 0)
			&& (strlen(line) == strlen(sendmsg))) {
		request_handler->command = SendMsg;
	} else if ((strncmp(changepw, line, strlen(recvmsg) - 3) == 0)
			&& (strlen(line) == strlen(recvmsg))) {
		request_handler->command = RecvMsg;
	}

	// invalid request; could not match the endpoint requested to known endpoint
	if (request_handler->command == InvalidCommand) {
		request_handler->status_code = NOT_FOUND;
		return request_handler;
	}

	// get second line
	line = strtok(NULL, "\n");

	char *content_length_headername = "content-length:";
	if (line == NULL
			|| strncasecmp(content_length_headername, line,
					strlen(content_length_headername)) != 0) {
		request_handler->status_code = BAD_REQUEST;
		return request_handler;
	}
	char *content_length_val = strchr(line, ':');

	if (content_length_val == NULL) {
		request_handler->status_code = BAD_REQUEST;
		return request_handler;
	}

	int content_length = 0;
	// handle optional whitespace between : and the length value
	if (*(content_length_val + 1) == ' ') {
		content_length = atoi(content_length_val + 2);
	} else {
		content_length = atoi(content_length_val + 1);
	}

	// get rest of the request
	// the first character should be a newline to indicate end of header section
	char *rest_of_req = strtok(NULL, "");
	if (rest_of_req == NULL || strncmp("\n", rest_of_req, 1)) {
		request_handler->status_code = BAD_REQUEST;
		return request_handler;
	}

	char *body = malloc(sizeof(char) * (content_length + 1));
	memset(body, 0, sizeof(content_length) + 1);
	strncpy(body, rest_of_req + 1, content_length);
	body[content_length] = '\0';

	request_handler->request_content = body;
	return request_handler;
}

/**
 * Checks a users submitted username and password against the username/password
 * that is stored for the user in a file on the server
 */
int check_credential(char *username, char *submitted_password) {

	// open file for username
	char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "passwords/%s.txt", username);
	FILE *pw_file = fopen(path_buf, "r");
	if (!pw_file) {
		printf("Could not open file containing hashed password for user.\n");
		return 0;
	}

	// read in the hashed/salted password
	int len_content = 200;
	char salted_hashed_pw[len_content + 1];
	size_t content = fread(salted_hashed_pw, 1, len_content, pw_file);
	salted_hashed_pw[content] = '\0';

	fclose(pw_file);

	// check hashed/salted content with contents of file
	char *c = crypt(submitted_password, salted_hashed_pw);
	if (strcmp(c, salted_hashed_pw) == 0)
		return 1;

	return 0;
}

/**
 * Parses the username and password from a request body.
 * Anticipates that the request body contains:
 * =======
 * username
 * password
 * ========
 */
int parse_credentials_from_request_body(char *request_body, char uname[],
		char pwd[], int buf_len) {

	char buf_cpy[strlen(request_body) + 1];
	strcpy(buf_cpy, request_body);
	buf_cpy[strlen(request_body)] = '\0';

	// set buffers to empty
	memset(uname, 0, buf_len);
	memset(pwd, 0, buf_len);

	// the username should be in the first line of the message
	int i;
	for (i = 0; i < strlen(buf_cpy) && buf_cpy[i] != '\n' && i < buf_len - 1; i++) {
		uname[i] = buf_cpy[i];
	}

	// it shouldn't be that the username is too long or the entirety of the request body
	// if this is the case, then something is wrong; only valid case is when the loop stops
	// on a new line.
	if (buf_cpy[i] != '\n') {
		fprintf(stderr, "Username could not be parsed from request body");
		return -1;
	}

	// read in password from the next line; here, we read in all content that can fit
	// into the password buf, or the rest of the content, or until a new line is hit,
	// whatever comes first.
	int j = 0;
	for (i = i + 1; i < strlen(buf_cpy) && buf_cpy[i] != '\n' && j < buf_len - 1; i++) {
		pwd[j] = buf_cpy[i];
		j++;
	}

	//  if nothing was read-in for the password, it's missing
	if (strlen(pwd) == 0) {
		fprintf(stderr, "Password could not be parsed from request body");
		return -1;
	}
	return 0;
}

/**
 * Creates request handler to contain parsed content of request.
 */
RequestHandler* init_request_handler() {

	RequestHandler *request_handler;

	if (!(request_handler = (RequestHandler*) malloc(sizeof(RequestHandler)))) {
		fprintf(stderr, "Could not create request handler for request.\n");
		return NULL;
	}
	request_handler->command = InvalidCommand;
	request_handler->status_code = 200;
	request_handler->request_content = NULL;
	request_handler->response_content = NULL;
	return request_handler;
}

/**
 * Frees allocated request handler struct.
 */
void free_request_handler(RequestHandler *request_handler) {
	if (request_handler == NULL) {
		return;
	}
	if (request_handler->request_content != NULL) {
		free(request_handler->request_content);
	}
	if (request_handler->response_content != NULL) {
		free(request_handler->response_content);
	}
	free(request_handler);
}
