#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "custom_utils.h"


/**
 * Removes any temporary files with file names beginning with "tmp_".
 * Returns 1 if successful, 0 if error.
 */
int remove_temporary_files_from_mailbox(char *username) {
	DIR *dir;
	struct dirent *de;
	int len_buf = 128;
	char path_buf[len_buf];
	sprintf(path_buf, "mailboxes/%s", username);

	if (!(dir = opendir(path_buf))) {
		fprintf(stderr, "Could not open directory of mailboxes "
				"for removing tmp files.\n");
		return 0;
	}

	char *tmp_signature = "tmp_";
	while ((de = readdir(dir)) != NULL) {
		// compare the filename with the signature of temporary files
		char *filename = de->d_name;
		if (!strncmp(filename, tmp_signature, strlen(tmp_signature))) {

			// if a temporary file is found, delete it
			memset(path_buf, 0, len_buf);
			sprintf(path_buf, "mailboxes/%s/%s", username, filename);
			remove(path_buf);
		}
	}
	closedir(dir);
	return 1;
}

/**
 * Write null terminated content to file at path specified.
 */
int save_content_to_file(char *content_buf, char *path) {

	FILE *p_file = NULL;
	if (!(p_file = fopen(path, "wb+"))) {
		printf("Failed to open new file for content\n");
		return 0;
	}

	int write = fwrite(content_buf, 1, strlen(content_buf), p_file);
	fclose(p_file);

	if (write != strlen(content_buf)) {
		printf("Could not write content to file\n");
		return 0;
	}
	return 1;
}
