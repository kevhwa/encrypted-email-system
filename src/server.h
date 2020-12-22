/*
 * server.h
 */

#ifndef SRC_SERVER_H_
#define SRC_SERVER_H_

#include <openssl/ssl.h>

int tcp_listen();

int save_client_msg(char* request_body);

#endif /* SRC_SERVER_H_ */
