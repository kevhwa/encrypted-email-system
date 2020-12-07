/*
 * create_ctx.h
 */

#ifndef SRC_CREATE_CTX_H_
#define SRC_CREATE_CTX_H_

#include <openssl/ssl.h>

SSL_CTX* create_ctx_client(char *certificate_file, char *private_key_file, int have_cert);

SSL_CTX* create_ctx_server(char *certificate_file, char *private_key_file, int verify_client);

#endif /* SRC_CREATE_CTX_H_ */
