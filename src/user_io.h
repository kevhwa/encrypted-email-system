#ifndef SRC_USER_IO_H_
#define SRC_USER_IO_H_

int get_username_password(int argc, char *argv[], char buff_pass[],
		char buff_user[], int max_len);

void get_hidden_pw(char *password, int max_len);

#endif /* SRC_USER_IO_H_ */
