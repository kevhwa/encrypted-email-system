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

#include "request_handler.h"

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


/**
 * Extracts the command and content from an incoming request
 * into a RequestHandler struct.
 */
RequestHandler* handle_recvd_msg(char *buf) {

	char *getcert = "POST /getcert HTTP/1.0";
	char *changepw = "POST /changepw HTTP/1.0";
	char *sendmsg = "POST /sendmsg HTTP/1.0";
	char *usercerts = "GET /certificates HTTP/1.0";
	char *recvmsg = "GET /message HTTP/1.0";

	// char *sendmsg_get = "GET /sendmsg HTTP/1.0";
	// char *sendmsg_post = "POST /sendmsg HTTP/1.0";

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
	} else if ((strncmp(sendmsg, line, strlen(sendmsg) - 3) == 0)
			&& (strlen(line) == strlen(sendmsg))) {
		request_handler->command = SendMsg;
	} else if ((strncmp(recvmsg, line, strlen(recvmsg) - 3) == 0)
			&& (strlen(line) == strlen(recvmsg))) {
		request_handler->command = RecvMsg;
	} else if ((strncmp(usercerts, line, strlen(usercerts) - 3) == 0)
			&& (strlen(line) == strlen(usercerts))) {
		request_handler->command = UserCerts;
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
 * Receives an HTTP response body using SSL_read.
 */
char* receive_ssl_response(SSL *ssl) {

	char buf[4096];
	int err = SSL_read(ssl, buf, sizeof(buf) - 1);
	buf[err] = '\0';
	fprintf(stdout, "Received %d chars of content:\n---\n%s----\n", err, buf);

	// get content_length
	char* header = (char*) malloc(strlen(buf) + 1);
	if (header == NULL) {
		fprintf(stderr, "malloc failed");
		return NULL;
	}
	strcpy(header, buf);
	

	// if server response not successful, return nothing
	char* line = strtok(header, "\n");
	if (!strstr(line, "200 Success")) {
		free(header);
		return NULL;
	}

	line = strtok(NULL, "\n");
	char *content_length_headername = "content-length:";
	if (line == NULL
			|| strncasecmp(content_length_headername, line,
					strlen(content_length_headername)) != 0) {
		printf("Server response header contained unexpected content\n");
		return NULL;
	}
	char *content_length_val = strchr(line, ':');
	if (content_length_val == NULL) {
		free(header);
		return NULL;
	}

	int content_length = 0;
	// handle optional whitespace between : and the length value
	if (*(content_length_val + 1) == ' ') {
		content_length = atoi(content_length_val + 2);
	} else {
		content_length = atoi(content_length_val + 1);
	}
	free(header);

	char *body = (char*) malloc(content_length + 1);
	if (!body) {
		return NULL;
	}
	memset(body, '\0', content_length + 1);

	int received = 0;

	printf("Ready to receive server certificate content...\n");
	while (received < content_length) {
		memset(buf, '\0', sizeof(buf));
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		fprintf(stdout, "Body received %d chars of content:\n---\n%s----\n", err, buf);
		if (err <= 0)
			break;
		strcat(body, buf);
		received += err;

		printf("Received %d so far, expecting %d\n", received, content_length);
	}
	return body;
}
