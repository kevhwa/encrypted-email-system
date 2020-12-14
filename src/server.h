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
  RecvMsg
};

int tcp_listen();

char* handle_recvd_msg(char* buf);

#endif /* SRC_SERVER_H_ */
