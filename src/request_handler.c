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
#define MAXHEADERSIZE 1048576

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
	request_handler->content_length = 0;
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
 * Receives an HTTP response body using SSL_read. 
 * Adapted from: https://stackoverflow.com/questions/38714363/read-html-response-using-ssl-read-in-c-http-1-0
 */
RequestHandler* parse_ssl_response(SSL *ssl) {
	char *getcert = "POST /getcert HTTP/1.0";
	char *changepw = "POST /changepw HTTP/1.0";
	char *sendmsg = "POST /sendmsg HTTP/1.0";
	char *usercerts = "GET /certificates HTTP/1.0";
	char *recvmsg = "GET /message HTTP/1.0";
 	char *success = "HTTP/1.0 200 Success";

	RequestHandler* request_handler = init_request_handler();
	if (!request_handler) {
		return NULL;
	}

	char buf[4096];
	char header[MAXHEADERSIZE];
	int bytes;
	int received = 0;
	int i = 0;
	char c[1];
	int line_length = 0;
	int is_valid_header = 1;
	do {
			bytes = SSL_read(ssl, c, 1);
			if (bytes  <= 0) break;
			if (c[0] == '\n') {
					if (line_length == 0) {
						break;
					} else {
						line_length = 0;
					}
			} else if (c[0] != '\r') {
				line_length++;
			};
			header[i++] = c[0];
			if (i == MAXHEADERSIZE) {
				fprintf(stderr, "Header size exceeds maximum allowed header size");
				is_valid_header = 0;
				break;
			}
			received += bytes;
	} while (1);

	if (!is_valid_header) return NULL;
	header[received] = '\0';

	char* header_cpy = malloc(strlen(header) + 1);
	if (header_cpy == NULL) {
		fprintf(stderr, "malloc failed");
		return NULL;
	}
	strcpy(header_cpy, header);

	// get first line of message
	char* line = strtok(header_cpy, "\n");
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
	} else if ((strncmp(success, line, strlen(success)) == 0)) {
		request_handler->command = SuccessResponse;		
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
	request_handler->content_length = content_length;
	free(header_cpy);

	char *body = (char*) malloc(content_length + 1);
	if (!body) {
		return NULL;
	}
	memset(body, '\0', content_length + 1);

	received = 0;
	while (received < content_length) {
		memset(buf, '\0', sizeof(buf));
		bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
		fprintf(stdout, "Body received %d chars of content:\n---\n%s----\n", bytes, buf);
		if (bytes <= 0) {
			printf("SSL response parser entered error state, exiting...\n");
			free_request_handler(request_handler);
			return NULL;
		}
		strcat(body, buf);
		received += bytes;
		printf("Received %d so far, expecting %d\n", received, content_length);
	}
	request_handler->request_content = body;
	return request_handler;
}
