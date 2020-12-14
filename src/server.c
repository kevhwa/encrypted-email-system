#include <stdio.h>
#include <strings.h>
#include <unistd.h>  
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <ctype.h>

#include "create_ctx.h"
#include "server.h"

#define SERVER_PORT 1000
#define ON  1
#define OFF 0

int tcp_listen();

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

        rqst = accept(sock, (struct sockaddr *)&client_addr, &alen);
        if (rqst < 0) {
            fprintf(stderr, "Unable to accept connection...\n");
        }
        fprintf(stdout, "Connection from %x, port %x\n", client_addr.sin_addr.s_addr, client_addr.sin_port);
        
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
        fprintf(stdout, "Received %d chars:'%s'\n", err, buf);

        /* Send data to the SSL client */
        char *msg  = "This message is from the SSL server\n";
        // char *msg = handle_recvd_msg(buf);
        err = SSL_write(ssl, msg, strlen(msg));

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(rqst);
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

    if (bind(sock, (struct sockaddr*) &sin, sizeof(sin)) < 0){
        perror("bind server failed");
		return -1;
    }
    
    if (listen(sock, 5) < 0) {
        perror("listen failed");
        return -1;
    }

    return sock;
}

char* handle_recvd_msg (char* buf) {
    char* bad_request = "HTTP/1.0 400 Bad Request\ncontent-length: 0\n\n"; 

    char* getcert = "POST /getcert HTTP/1.0";
    char* changepw = "POST /changepw HTTP/1.0";
    char* sendmsg = "POST /sendmsg HTTP/1.0";
    char* recvmsg = "POST /recvmsg HTTP/1.0";

    char* buf_cpy = (char*) malloc(strlen(buf) + 1);
    strcpy(buf_cpy, buf);
    buf_cpy[strlen(buf)] = '\0';

    // get first line of message    
    char* line = strtok(buf_cpy, "\n");
    if (line == NULL) {
        return bad_request;
    }

    enum server_command command = InvalidCommand;
    if (strcmp(getcert, line) == 0) {
        command = GetCert;
    } else if (strcmp(changepw, line) == 0) { 
        command = ChangePW;
    } else if (strcmp(sendmsg, line) == 0) {
        command = SendMsg;
    } else if (strcmp(recvmsg, line) == 0) {
        command = RecvMsg;
    }

    // invalid request
    if (command == InvalidCommand) { 
        return "HTTP/1.0 404 Not Found\ncontent-Length: 0\n\n";
    }

    // get second line
    line = strtok(NULL, "\n");

    char* content_length_headername = "content-length:";
    if (line == NULL || strncasecmp(content_length_headername, line, strlen(content_length_headername)) != 0) {
        return bad_request;
    }
    char* content_length_val = strchr(line, ':');
    if (content_length_val == NULL) {
        return bad_request;
    }
    int content_length = atoi(content_length_val + 1);

    // get rest of the request
    char* rest_of_req = strtok(NULL, "");

    // the first character should be a newline to indicate end of header section
    if (rest_of_req == NULL || strncmp("\n", rest_of_req, 1)) {
        return bad_request;
    }
    char* body = malloc(sizeof(content_length) + 1);
    strncpy(body, rest_of_req + 1, content_length);
    body[content_length] = '\0';
    return body;
}