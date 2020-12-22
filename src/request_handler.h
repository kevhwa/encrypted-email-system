/*
 * request_handler.h
 */

#ifndef SRC_REQUEST_HANDLER_H_
#define SRC_REQUEST_HANDLER_H_

#include <openssl/ssl.h>


#define BAD_REQUEST 400
#define NOT_FOUND 404

enum server_command {
	InvalidCommand, 
	GetCert,
	ChangePW,
	SendMsg,
	RecvMsg,
	UserCerts,
	SuccessResponse,
};

typedef struct request_handler {
	enum server_command command;
	int status_code;
	int content_length;
	char *request_content;
	char *response_content;
} RequestHandler;

typedef struct certificates_handler {
	int num;
	char** certificates;
	char** recipients;
} CertificatesHandler;

int save_client_msg(char* request_body);

RequestHandler* init_request_handler();

void free_request_handler(RequestHandler *request_handler);

RequestHandler* parse_ssl_response(SSL *ssl);

#endif /* SRC_REQUEST_HANDLER_H_ */
