#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>  
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <ctype.h>
// #include <crypt.h>  // use if using a linux machine

#include "create_ctx.h"
#include "server.h"

#define SERVER_PORT 8080
#define ON  1
#define OFF 0
#define BAD_REQUEST 400
#define NOT_FOUND 404

const char *bad_request_resp = "HTTP/1.0 400 Bad Request\nContent-Length: 0\n\n";
const char *not_found_resp = "HTTP/1.0 404 Not Found\nContent-Length: 0\n\n";
const char *internal_error_resp = "HTTP/1.0 500 Internal Server Error\nContent-Length: 0\n\n";
int parse_credentials_from_request_body(char *request_body, char uname[], 
            char pwd[], int buf_len);

int tcp_listen();
RequestHandler* init_request_handler();
void free_request_handler(RequestHandler *request_handler);
int check_credential(char *username, char *submitted_password);

int main(int argc, char **argv) {
	int err;
	BIO *sbio;
	SSL *ssl;
	char *s;
	SSL_CTX *ctx;
	int sock, rqst;
	int verify_client = OFF;

	// create the SSL context
	ctx = create_ctx_server(NULL, NULL, 0);

	// create the TCP socket
	if ((sock = tcp_listen()) < 0) {
		return 2;
	}

	for (;;) {
		struct sockaddr_in client_addr;
		socklen_t alen = sizeof(client_addr);

		fprintf(stdout, "\nWaiting for connection\n");
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

		if (verify_client) {
			// do something here to verify the client
			// this might be a helper function used by multiple programs
		}

		char buf[4096];
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		buf[err] = '\0';
		fprintf(stdout, "Received %d chars of content:\n---\n%s----\n", err, buf);

		char cert_buf[4096];
		int temp = SSL_read(ssl, cert_buf, sizeof(cert_buf) - 1);
		cert_buf[temp] = '\0';
		fprintf(stdout, "\nCSR Received:\n%s\n", cert_buf);

		// char path_buf[100];
		// snprintf(path_buf, sizeof(path_buf), "test.pem");

		// FILE *x509_file = fopen(path_buf, "wb");
		// if(!x509_file) {
		//     printf("Unable to open cert req file for writing.\n");
		//     return NULL;
		// }

		// /* Write the certificate to disk. */
		// int ret = PEM_write_X509_REQ(x509_file, (X509_REQ *) cert_buf);
		// fclose(x509_file);

		// printf("size of cert buf %ld\n", strlen(cert_buf));
		// cert_buf[err] = '\0';
		// fprintf(stdout, "Received certificate - %d chars: %s\n", err, cert_buf);

		// --- Send data back to the SSL client ---

		RequestHandler *request_handler = handle_recvd_msg(buf);

		if (!request_handler) {
			err = SSL_write(ssl, internal_error_resp, strlen(internal_error_resp));
		} else if (request_handler->status_code == BAD_REQUEST) {
			err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
		} else if (request_handler->status_code == NOT_FOUND) {
			err = SSL_write(ssl, not_found_resp, strlen(not_found_resp));
		} else {
            // handle the request

            int max_auth_len = 20;
            char uname_buf[max_auth_len];
            char pwd_buf[max_auth_len];
            if (parse_credentials_from_request_body(request_handler->request_content, 
                    uname_buf, pwd_buf, max_auth_len) < 0) {
                err = SSL_write(ssl, bad_request_resp, strlen(bad_request_resp));
            }

            printf("Authentication result: %d\n", check_credential(uname_buf, pwd_buf));
            int len_content = strlen(request_handler->request_content);
		    err = SSL_write(ssl, request_handler->request_content, len_content);
        }

		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(rqst);
		free_request_handler(request_handler);
	}
	close(sock);
	SSL_CTX_free(ctx);
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
int check_credential(char *username, char *submitted_password){

    // open file for username
    char path_buf[100];
	snprintf(path_buf, sizeof(path_buf), "./server-dir/passwords/%s.txt", username);
	FILE *pw_file = fopen(path_buf, "r");
	if (!pw_file) {
		printf("Could not open file containing hashed password for user.\n");
		return 0;
	}

    // read in the hashed/salted password (it will be 106 characters)
    int len_content = 106;
    char salted_hashed_pw[len_content + 1];
	size_t content = fread(salted_hashed_pw, 1, len_content, pw_file);
	salted_hashed_pw[content] = '\0';

	fclose(pw_file);

    // check hashed/salted content with contents of file
    char *c = crypt(submitted_password, salted_hashed_pw);

    printf("Read password: %s\n", salted_hashed_pw);
    printf("Recomputed password: %s\n", c);

    if (strncmp(c, salted_hashed_pw, strlen(salted_hashed_pw)) == 0)
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

    printf("Username: %s\n", uname);
    printf("Password: %s\n", pwd);
    return 0;
}

/**
 * Creates request handler to contain parsed content of request.
 */
RequestHandler* init_request_handler() {

	RequestHandler *request_handler;

	if (!(request_handler = (RequestHandler*) malloc(sizeof(RequestHandler)))) {
		fprintf(stderr, "Could not create request handler fore request.\n");
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
