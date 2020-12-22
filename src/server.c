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
#include <sys/time.h>

#ifndef __APPLE__
#include <crypt.h>  // needs to be included if using linux machine
#endif

#include "user_io.h"
#include "create_ctx.h"
#include "server.h"
#include "request_handler.h"

#define AUTH_PORT 8081
#define NO_AUTH_PORT 8080
#define ON  1
#define OFF 0
#define CERTIFICATE_FILE "ca/certs/ca-chain.cert.pem"
#define TRUSTED_CA_FILE "ca/certs/ca-chain.cert.pem"
#define PRIVATE_KEY_FILE "ca/private/intermediate.key.pem"
#define MAX_MAIL_SIZE 4096

const char *bad_request_resp = "HTTP/1.0 400 Bad Request\nContent-Length: 0\n\n";
const char *not_found_resp = "HTTP/1.0 404 Not Found\nContent-Length: 0\n\n";
const char *unauthorized_resp = "HTTP/1.0 401 Unauthorized\nContent-Length: 0\n\n";
const char *conflict_resp = "HTTP/1.0 409 Conflict\nContent-Length: %d\n\n";
const char *internal_error_resp = "HTTP/1.0 500 Internal Server Error\nContent-Length: 0\n\n";
const char *success_template = "HTTP/1.0 200 Success\nContent-Length: %d\n\n";
const char *success_template_with_content = "HTTP/1.0 200 Success\nContent-Length: %d\n\n%s";

int tcp_listen(int port);
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
int awaiting_messages_for_client(char *path, char *pending_file_buf, int save_pending_file);
int64_t get_current_time();

int main(int argc, char **argv) {
	int err;
	BIO *sbio;
	SSL *ssl;
	char *s;
	SSL_CTX *ctx;
	int sock, rqst;
	int port;

	// create the SSL context, with option to use authentication
	if (argc > 1 && strcmp(argv[1], "-a") == 0) {
		ctx = create_ctx_server(CERTIFICATE_FILE, PRIVATE_KEY_FILE, TRUSTED_CA_FILE, ON);
		port = AUTH_PORT;
	}
	else {
		ctx = create_ctx_server(CERTIFICATE_FILE, PRIVATE_KEY_FILE, NULL, OFF);
		port = NO_AUTH_PORT;
	}

	// create the TCP socket
	if ((sock = tcp_listen(port)) < 0) {
		return 2;
	}

	// set socket timeout
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	if (port == NO_AUTH_PORT) {
		fprintf(stdout, "\nServer started (username/password required)!\n");
	} else {
		fprintf(stdout, "\nServer started (client certificate checks enabled)!\n");
	}

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

		if (setsockopt(rqst, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) != 0) {
			fprintf(stdout, "Error setting timeout\n");
		}

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
		fprintf(stdout, "Received %d chars of content:\n---\n%s----\n", err, buf);
		RequestHandler *request_handler = handle_recvd_msg(buf);

		// --- Validate request and send resp back to the SSL client ---
		int max_auth_len = 20;
		char uname_buf[max_auth_len];
		char pwd_buf[max_auth_len];

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

		if (request_handler->command == ChangePW || request_handler->command == GetCert) {
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
			if ((err = awaiting_messages_for_client(path, NULL, 0)) != 0) {
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
		}

		else if (request_handler->command == UserCerts) {
			// --- Get list of recipients from space-separated request body ---//
			char certs_recpts[10][20] = {{'\0'}};
			int pos = 0;
	
			char* content_copy = malloc(strlen(request_handler->request_content) + 1);
			sprintf(content_copy, "%s", request_handler->request_content);

			char* recipient = strtok(content_copy, " ");
			int no_recpts = 0;
			int recipient_exists;
			while (recipient != NULL) {
				if (no_recpts >= 10) {
					fprintf(stderr, "Too many recipients received, ending session...\n");
					err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
					goto CLEANUP;
				}
				// recipient should not exceed max length acceptable length
				if (strlen(recipient) >= 20 || strlen(recipient) < 5) {
					fprintf(stderr, "Skipping recipient %s of invalid length\n", recipient);
					recipient = strtok(NULL, " ");
					continue;
				}
				
				// remove duplicate recipients
				recipient_exists = 0;
				for (int k = 0; k < no_recpts; k++) {
					if (strcmp(certs_recpts[k], recipient) == 0) {
						recipient_exists = 1;
						break;
					}
				}
				if (recipient_exists) {
					fprintf(stdout, "Skipping duplicate recipient %s\n", recipient);
					recipient = strtok(NULL, " ");
					continue;
				}

				fprintf(stdout, "Added recipient %s\n", recipient);
				strcpy(certs_recpts[pos], recipient);
				pos++;
				no_recpts++;
				recipient = strtok(NULL, " ");
			}
			free(content_copy);
			if (no_recpts == 0) {
				// no recipients
				fprintf(stderr, "No valid recipients found, ending session...\n");
				err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
				goto CLEANUP;
			}

			// --- Construct response body for UserCerts ---//
			int max_size = 100000;
			char* response_body = (char*) malloc(sizeof(char) * max_size);
			snprintf(response_body, max_size, "%d\n", no_recpts);
			int response_size = strlen(response_body) + 1;

			char* cert_separator = "\n";
			int cert_separator_len = strlen(cert_separator);
			char path_buf[100];
			FILE* cert_fp;
			int file_size;
			int new_size;
			char* cert_data;
			for (int i = 0; i < no_recpts; i++) {
				memset(path_buf, '\0', sizeof(path_buf));
				snprintf(path_buf, sizeof(path_buf), "mailboxes/%s/%s.cert.pem", certs_recpts[i], certs_recpts[i]);

				fprintf(stdout, "Looking for certificate of recipient '%s' here: %s\n", certs_recpts[i], path_buf);

				cert_fp = fopen(path_buf, "r");
				if (!cert_fp) {
					fprintf(stdout, "Could not find certificate for recipient '%s'\n", certs_recpts[i]);
					cert_data = "NOCERT";
				}
				else {
					fprintf(stdout, "Found certificate for recipient %s\n", certs_recpts[i]);
					fseek(cert_fp, 0, SEEK_END);
					file_size = ftell(cert_fp);
					fseek(cert_fp, 0, SEEK_SET);
					cert_data = (char*) malloc(sizeof(char) * (file_size + 1));
					fread(cert_data, sizeof(char), file_size, cert_fp);
					cert_data[file_size] = '\0';
				}
				new_size = response_size + strlen(certs_recpts[i])
						+ strlen(cert_data) + cert_separator_len + 1;

				if (max_size <= new_size) {
					response_body = realloc(response_body, 2 * new_size);
					max_size = 2 * new_size;
					if (!response_body) {
						free(response_body);
						fprintf(stderr, "realloc failed\n");
						exit(1);
					}
				}
				
				strcat(response_body, certs_recpts[i]);
				strcat(response_body, "\n");
				strcat(response_body, cert_data);
				strcat(response_body, cert_separator);
				response_size = new_size;
				if (cert_fp) {
					free(cert_data);
					fclose(cert_fp);
				}
			}
			char content_buf[4096];
			sprintf(content_buf, success_template, response_size);
			err = SSL_write(ssl, content_buf, strlen(content_buf));
			err = SSL_write(ssl, response_body, response_size);

			fprintf(stdout, "Sent certificates:\n---\n%s%s\n---\n", content_buf, response_body);
			fflush(stdout);
			free(response_body);

			// --- Receive SendMsg Commands ---//
			while (1) {
				char* body = receive_ssl_response(ssl, "POST /sendmsg HTTP/1.0");
				if (body == NULL) {
					err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
					goto CLEANUP;
				}
				if (strlen(body) == 0) {
					break;
				}
				if (0 == save_client_msg(body)) {
					err = SSL_write(ssl, content_buf, strlen(content_buf));
				} else {
					sprintf(content_buf, internal_error_resp, 0);
					err = SSL_write(ssl, content_buf, strlen(content_buf));
				}
			}
		}
		else if (request_handler->command == SendMsg) {
			// SendMsg should not be called directly
			err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
			goto CLEANUP;
    	}
		else if (request_handler->command == RecvMsg) {
			// client making request is only content in request body; if request
			// body is too long, this doesn't make sense; usernames are always < 20 chars
			char *requesting_client = request_handler->request_content;
			if (strlen(requesting_client) > 50) {
				err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
				goto CLEANUP;
			}
			
			char file_path_buf[257]; // max size of a filepath, plus null terminator
			snprintf(file_path_buf, sizeof(file_path_buf), "mailboxes/%s", requesting_client);
			char filename_buf[100]; 
			memset(filename_buf, 0, sizeof(filename_buf));

			// find it there are any awaiting messages for the client
			int awaiting_messages = awaiting_messages_for_client(file_path_buf, filename_buf, 1);
			if (awaiting_messages < 0) {

				// this is an error case; likely the username provided was wrong in the request body
				err = SSL_write(ssl, not_found_resp, strlen(not_found_resp));
				goto CLEANUP;
			} 
			else if (!awaiting_messages) {
				// if there are no awaiting messages for the client, this is OK, send back no content
				char no_msg_buf[100];
				sprintf(no_msg_buf, success_template, 0);
				SSL_write(ssl, no_msg_buf, strlen(no_msg_buf));
				goto CLEANUP;
			}

			// ------ Open a file and parse the contents to retrieve information ----- //
			memset(file_path_buf, 0, sizeof(file_path_buf));
			sprintf(file_path_buf, "mailboxes/%s/%s", requesting_client, filename_buf);
			FILE *fp = fopen(file_path_buf, "rb+");
			if (!fp) {
				err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
				goto CLEANUP;
			}
			
			// read in entire file
			long file_size = 0;
			fseek(fp, 0, SEEK_END);
			file_size = ftell(fp); 
			fseek(fp, 0, SEEK_SET); 
			char file_contents[file_size];
			fread(file_contents, 1, file_size, fp);
			fclose(fp);
			
			// first line of the file will is a sender
			char sender[50];
			int i = 0;
			while (i < file_size && i < sizeof(sender) && file_contents[i] != '\n') {
				sender[i] = file_contents[i];
				i++;
			}
			sender[i] = '\0';
		
			if (file_contents[i] != '\n' || i + 1 >= file_size) {
				// this is probably a problem
				err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
				goto CLEANUP;
			}

			// Get the start of the message content
			char *beginning_of_msg_content = &file_contents[++i];
			
		   // -------- Read in the sender's certificate ------ //
			char cert_path_buf[257];
			char read_certbuf[4096];
			int read_len = 0;
			snprintf(cert_path_buf, sizeof(cert_path_buf), "mailboxes/%s/%s.cert.pem", sender, sender);

			if ((read_len = read_x509_cert_from_file(read_certbuf,
					sizeof(read_certbuf), cert_path_buf)) == 0) {

				err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
				goto CLEANUP;
			}

			// ---- Provide the sender's cert, the message content back to client ---- //
			char success_buf[256];
			int content_len = strlen(sender) + read_len + file_size - i;
			sprintf(success_buf, success_template_with_content, content_len, sender);
			SSL_write(ssl, success_buf, strlen(success_buf));
			SSL_write(ssl, read_certbuf, read_len);
			SSL_write(ssl, beginning_of_msg_content, file_size - i);

			// delete the message once it is sent to the user
			if (remove(file_path_buf) != 0) {
				fprintf(stderr, "Read file could not be removed from server!\n");
			}
		}

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
 * Count the number of messages awaiting for client. If an awaiting
 * message exists, copy the name of the file into the char array named
 * pending_file.
 */
int awaiting_messages_for_client(char *path, char *pending_file_buf, int save_pending_file) {
	int message_count = 0;
	DIR *dir;
	struct dirent *de;

	// These are files to ignore in the count
	char *parent = "..";
	char *current = ".";
	char *known_cert_ext = ".cert.pem";
	char *known_csr_ext = ".csr.pem";

	if (!(dir = opendir(path))) {
		fprintf(stderr, "Could not open the following directory "
				"to check for unread messages: %s.\n", path);
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
			if (save_pending_file && !strlen(pending_file_buf)) {\
				// save the first pending file to the pending_file_buf
				memcpy(pending_file_buf, filename, strlen(filename));
				pending_file_buf[strlen(filename)] = '\0';
			}
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
int tcp_listen(int port) {

	struct sockaddr_in sin;
	int sock;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("cannot create server socket");
		return -1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

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

	// handle accidental case when \n is read in
	if (salted_hashed_pw[strlen(salted_hashed_pw) - 1] == '\n') {
		salted_hashed_pw[strlen(salted_hashed_pw) - 1] = '\0';
	}

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
 * Saves message from client in SendMsg request.
 */
int save_client_msg(char* request_body) {
	// first line is the sender
	char* line = strtok(request_body, "\n");
	char* sender = malloc(strlen(line) + 1);
	strcpy(sender, line);

	// second line is the recipient
	line = strtok(NULL, "\n");
	char* recipient = malloc(strlen(line) + 1);
	strcpy(recipient, line);
		
	char path[200];
	snprintf(path, sizeof(path), "mailboxes/%s/%ld", recipient, get_current_time());
	FILE* fp = fopen(path, "w");
	if (!fp) {
		free(sender);
		free(recipient);
		fprintf(stderr, "Could not open file for recipient %s", recipient);
		return -1;
	}

	fwrite(sender, 1, strlen(sender), fp);
	fwrite("\n", 1, 1, fp);
	// write rest of the encrypted message
	line = strtok(NULL, "");
	fwrite(line, 1, strlen(line), fp);
	fclose(fp);
	fprintf(stdout, "Saved encrypted message to file %s\n", path);
	free(recipient);
	free(sender);
	return 0;
}

/**
 * Get current time in milliseconds. Credit: https://stackoverflow.com/questions/10098441/get-the-current-time-in-milliseconds-in-c
 */
int64_t get_current_time() {
  struct timeval time;
  gettimeofday(&time, NULL);
  int64_t s1 = (int64_t)(time.tv_sec) * 1000;
  int64_t s2 = (time.tv_usec / 1000);
  return s1 + s2;
}
