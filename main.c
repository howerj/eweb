/****************************************************************************
 ** Released under The MIT License (MIT). This code comes without warranty, **
 ** but if you use it you must provide attribution back to David's Blog     **
 ** at http://www.codehosting.net   See the LICENSE file for more details.  **
 ****************************************************************************/

#include "eweb.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h> // needed to run server on a new thread

#define FILE_CHUNK_SIZE (1024)
#define BIGGEST_FILE    (100l * 1024l * 1024l)

static const struct {
	char *ext;
	char *filetype;
} extensions[] = {
	{  "gif",    "image/gif" },
	{  "jpg",    "image/jpeg" },
	{  "jpeg",   "image/jpeg" },
	{  "png",    "image/png" },
	{  "ico",    "image/x-icon" },
	{  "zip",    "application/zip" },
	{  "gz",     "application/gzip" },
	{  "tar",    "application/x-tar" },
	{  "htm",    "text/html" },
	{  "html",   "text/html" },
	{  "js",     "text/javascript" },
	{  "txt",    "text/plain" },
	{  "css",    "text/css" },
	{  "map",    "application/json" },
	{  "woff",   "application/font-woff" },
	{  "woff2",  "application/font-woff2" },
	{  "ttf",    "application/font-sfnt" },
	{  "svg",    "image/svg+xml" },
	{  "eot",    "application/vnd.ms-fontobject" },
	{  "mp4",    "video/mp4" },
	{  NULL,     NULL }
};

static pthread_t server_thread_id;

static void log_filter(log_type type, char *s1, char *s2, int socket_fd) {
	if (type != ERROR)
		return;
	printf("ERROR: %s: %s (errno=%d pid=%d socket=%d)\n", s1, s2, errno, getpid(), socket_fd);
}

// a simple API, it receives a number, increments it and returns the response
static void send_api_response(eweb_os_t *w, struct hitArgs *args, char *path, char *request_body) {
	assert(w);
	UNUSED(request_body);
	char response[4] = { 0 };

	if (args->form_value_counter == 1 && !strncmp(eweb_form_name(args, 0), "counter", strlen(eweb_form_name(args, 0)))) {
		int c = atoi(eweb_form_value(args, 0));
		if (c > 99 || c < 0)
			c = 0;
		sprintf(response, "%d", ++c);
		eweb_ok_200(w, args, "\nContent-Type: text/plain", response, path);
	} else {
		eweb_forbidden_403(w, args, "Bad request");
	}
}

static void send_file_response(eweb_os_t *w, struct hitArgs *args, char *path, char *request_body, int path_length) {
	assert(w);
	UNUSED(request_body);
	char *content_type = NULL;
	string_t *response = new_string(FILE_CHUNK_SIZE);

	if (args->form_value_counter > 0 && eweb_string_matches_value(args->content_type, "application/x-www-form-urlencoded")) {
		string_add(response, "<html><head><title>Response Page</title></head>");
		string_add(response, "<body><h1>Thanks...</h1>You sent these values<br/><br/>");

		for (int v = 0; v < args->form_value_counter; v++) {
			string_add(response, eweb_form_name(args, v));
			string_add(response, ": <b>");
			string_add(response, eweb_form_value(args, v));
			string_add(response, "</b><br/>");
		}

		string_add(response, "</body></html>");
		eweb_ok_200(w, args, "\nContent-Type: text/html", string_chars(response), path);
		string_free(response);
		return;
	}
	// work out the file type and check we support it
	for (size_t i = 0; extensions[i].ext != 0; i++) {
		const long len = strlen(extensions[i].ext);
		if (!strncmp(&path[path_length - len], extensions[i].ext, len)) {
			content_type = extensions[i].filetype;
			break;
		}
	}
	if (!content_type) {
		string_free(response);
		eweb_forbidden_403(w, args, "file extension type not supported");
		return;
	}

	const int file_id = open(path, O_RDONLY);
	if (file_id == -1) {
		string_free(response);
		eweb_notfound_404(w, args, "failed to open file");
		return;
	}

	long len = lseek(file_id, (off_t) 0, SEEK_END);
	lseek(file_id, (off_t) 0, SEEK_SET);

	if (len > BIGGEST_FILE) {
		string_free(response);
		eweb_forbidden_403(w, args, "files this large are not supported");
		return;
	}

	string_add(response, "HTTP/1.1 200 OK\nServer: eweb\n");
	string_add(response, "Connection: close\n");
	string_add(response, "Content-Type: ");
	string_add(response, content_type);
	eweb_write_header(w, args->socketfd, string_chars(response), len);

	// send file in blocks
	while ((len = read(file_id, response->ptr, FILE_CHUNK_SIZE)) > 0) {
		if (write(args->socketfd, response->ptr, len) <= 0)
			break;
	}
	string_free(response);
	close(file_id);

	// allow socket to drain before closing
	sleep(1);
}


// decide if we need to send an API response or a file...
static int send_response(eweb_os_t *w, struct hitArgs *args, char *path, char *request_body, http_verb type) {
	assert(w);
	UNUSED(type);
	const size_t path_length = strlen(path);
	if (!strncmp(&path[path_length - 3], "api", 3)) {
		send_api_response(w, args, path, request_body);
		return EWEB_OK;
	}
	if (path_length == 0) {
		send_file_response(w, args, "index.html", request_body, 10);
		return EWEB_OK;
	}
	send_file_response(w, args, path, request_body, path_length);
	return EWEB_OK;
}

static void *server_thread(void *args) {
	pthread_detach(pthread_self());
	char *arg = (char *)args;
	eweb_os_t w = eweb_os;
	eweb_server(&w, atoi(arg), send_response, &log_filter);
	return NULL;
}

static void close_down(void) {
	eweb_server_kill(NULL);
	pthread_cancel(server_thread_id);
	puts("Bye bye");
}

static void wait_for_key(void) {
	fgetc(stdin);
	close_down();
}

int main(int argc, char **argv) {
	eweb_os_t w = eweb_os;
	if (argc < 2 || !strncmp(argv[1], "-h", 2)) {
		printf("hint: dweb [port number]\n");
		return 0;
	}
	if (argc > 2 && !strncmp(argv[2], "-d", 2)) { // don't read from the console or log anything
		eweb_server(&w, atoi(argv[1]), send_response, NULL);
	} else {
		if (pthread_create (&server_thread_id, NULL, server_thread, argv[1]) != 0) {
			puts("Error: pthread_create could not create server thread");
			return 0;
		}

		puts("dweb server started\nPress a key to quit");
		wait_for_key();
	}
}


