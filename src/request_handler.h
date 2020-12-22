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
	UserCerts
};

typedef struct request_handler {
	enum server_command command;
	int status_code;
	char *request_content;
	char *response_content;
} RequestHandler;

int save_client_msg(char* request_body);

RequestHandler* handle_recvd_msg(char *buf);

RequestHandler* init_request_handler();

void free_request_handler(RequestHandler *request_handler);

char* receive_ssl_response(SSL *ssl);

#endif /* SRC_REQUEST_HANDLER_H_ */
