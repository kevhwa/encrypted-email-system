#ifndef SRC_USER_IO_H_
#define SRC_USER_IO_H_

typedef struct certificates_handler {
	int num;
	char** certificates;
	char** recipients;
} CertificatesHandler;

int get_username_password(int argc, char *argv[], char buff_pass[],
		char buff_user[], int max_len);

void get_hidden_pw(char *msg, char *password, int max_len);

int get_sendmsg_args(int argc, char *argv[], char buff_path[],
	char buff_rcpts[], int max_len_path, int max_len_rcpt, int max_len_rcpts);

#endif /* SRC_USER_IO_H_ */
