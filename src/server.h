/*
 * server.h
 */

#ifndef SRC_SERVER_H_
#define SRC_SERVER_H_

#include <openssl/ssl.h>

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

int tcp_listen();

RequestHandler* handle_recvd_msg(char *buf);

#endif /* SRC_SERVER_H_ */
