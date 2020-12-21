/*
 * create_ctx.c
 */
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/**
 * Create a client context, given a certificate file, private key file. If
 * certificate exists, have_cert = 1, else have_cert = 0 will run without
 * a specified certificate and private key file.
 */
SSL_CTX* create_ctx_client(char *certificate_file, char *private_key_file,
			char *trusted_ca, int have_cert) {

	/* initalize global system */
	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);

	/* Load the trusted CAs */
	// update file path to client dir later; note that only the ca-chain.cert.pem works
	SSL_CTX_load_verify_locations(ctx, trusted_ca, NULL); 
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx, 1);

	if (have_cert) {
		if (SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM) != 1) {
			SSL_CTX_free(ctx);
			printf("Could not load certificate file.\n");
			return NULL;
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM) != 1) {
			SSL_CTX_free(ctx);
			printf("Could not load private key file.\n");
			return NULL;
		}

	}
	return ctx;
}

/**
 * Create a server context, given a certificate file and private key. 
 * If the client's certificate should be verified, set verfiy_client = 1.
 */
SSL_CTX* create_ctx_server(char *certificate_file, char *private_key_file, 
			char *trusted_ca, int verify_client) {

	/* initalize global system */
	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);

	/* Load the keys and certificates */
	SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM);

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		SSL_CTX_free(ctx);
		exit(1);
  	}

	if (verify_client) {
		SSL_CTX_load_verify_locations(ctx, trusted_ca, NULL);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ctx, 2);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_default_verify_dir(ctx);
	}
	return ctx;
}

