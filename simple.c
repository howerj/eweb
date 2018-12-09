#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eweb.h"

static int simple_response(eweb_os_t *w, struct eweb_os_hit_args *args, char *path, char *request_body, http_verb type) {
	UNUSED(request_body);
	UNUSED(type);
	eweb_ok_200(w, args, "\nContent-Type: text/html",
	       "<html><head><title>Test Page</title></head>"
	       "<body><h1>Testing...</h1>This is a test response.</body>"
	       "</html>", path);
	return EWEB_OK;
}

int main(int argc, char **argv) {
	eweb_os_t w = eweb_os;

	if (argc != 2 || !strcmp(argv[1], "-?")) {
		printf("hint: %s [port number]\n", argv[0]);
		return EXIT_FAILURE;
	}
	return eweb_server(&w, atoi(argv[1]), simple_response) == EWEB_OK ?
		EXIT_SUCCESS :
		EXIT_FAILURE ;
}

