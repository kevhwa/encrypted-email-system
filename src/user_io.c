#include <stdio.h>
#include <strings.h>
#include <termios.h>
#include <unistd.h>

#include "user_io.h"


int fill_username_password_from_args(int argc, char *argv[], char buff_pass[], 
                char buff_user[], int max_len);

void get_hidden_pw(char *password, int max_len);



/**
 * Fills buff_pass and buff_user buffers for password and username with
 * content from submitted args, and/or prompts user for password.
 * Returns 0 if successfull, -1 if failure.
 */
int get_username_password(int argc, char *argv[], char buff_pass[], 
                char buff_user[], int max_len) {
    
    // set content to nothing; ready to accept input
    memset(&buff_pass[0], 0, max_len);
    memset(&buff_user[0], 0, max_len);

    if (fill_username_password_from_args(argc, argv, buff_pass, 
                buff_user, max_len) < 0) {
        return -1;
    }
    
    if (strlen(buff_pass) == 0) {
        get_hidden_pw(buff_pass, max_len);
    }
    
    return 0;
}

/**
 * Parse the flags and args from what was submitted by the user on the 
 * command line. Errors will be reported if format is not what is expected.
 */
int fill_username_password_from_args(int argc, char *argv[], char buff_pass[], 
                char buff_user[], int max_len) {

    if (argc < 3) {
        fprintf(stderr, "One or more arguments are missing.\n");
        return -1;
    }

    for (int i = 1; i < argc; i++) {

        // check that -u flag is provided as second arg
        if (i == 1 & strncmp(argv[i], "-u", 2) != 0)  {
            fprintf(stderr, "Unexpected argument order.\n");
            return -1;
        }
        // check that -p flag is provided as 4th arg
        else if (i == 3 & strncmp(argv[i], "-p", 2) != 0) {
            fprintf(stderr, "Unexpected argument order.\n");
            return -1; 
        }
        // consider the second arg as the username
        else if (i == 2) {
            if (max_len < strlen(argv[i])) {
                fprintf(stderr, "Username of unexpected length.\n");
                return -1;
            }
            memcpy(buff_user, argv[i], strlen(argv[i]));
            buff_user[strlen(argv[i])] = '\0';
        }
        // consider the fourth arg as the password
        else if (i == 4) {
            if (max_len < strlen(argv[i])) {
                fprintf(stderr, "Password of unexpected length.\n");
                return -1;
            }
            memcpy(buff_pass, argv[i], strlen(argv[i]));
            buff_pass[strlen(argv[i])] = '\0';
        }
    }
    return 0;
}

/**
 * Get a password from a user (hidden) on the command line.
 */
void get_hidden_pw(char *password, int max_len) {

	static struct termios old_terminal;
	static struct termios new_terminal;

	printf("Please provide your password (less than %d characters): ", max_len);

	// get settings of the actual terminal
	tcgetattr(STDIN_FILENO, &old_terminal);

	// do not echo the characters
	new_terminal = old_terminal;
	new_terminal.c_lflag &= ~(ECHO);

	// set this as the new terminal options
	tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

	// get the password from the user
	int c;
	int i = 0;
    while ((c = getchar()) != '\n' && c != EOF && i < max_len - 1){
        password[i++] = c;
    }
    password[i] = '\0';
    printf("\n");

	// go back to the old settings
	tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}
