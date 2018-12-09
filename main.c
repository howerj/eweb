/**@file      eweb.c
 * @license   MIT
 * @copyright 2015-2016 http://www.codehosting.net
 * @copyright 2018      Richard James Howe (Changes)
 * @brief eweb driver, including a minimal API example */
#include "eweb.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_CHUNK_SIZE (1024)
#define BIGGEST_FILE    (100l * 1024l * 1024l)

static const char *find_file_type_by_file_extension(const char *path, size_t path_length) {
	assert(path);
	static const struct {
		char *ext;
		char *filetype;
	} extensions[] = {
		{ "gif",   "image/gif" },
		{ "jpg",   "image/jpeg" },
		{ "jpeg",  "image/jpeg" },
		{ "png",   "image/png" },
		{ "ico",   "image/x-icon" },
		{ "zip",   "application/zip" },
		{ "gz",    "application/gzip" },
		{ "tar",   "application/x-tar" },
		{ "htm",   "text/html" },
		{ "html",  "text/html" },
		{ "js",    "text/javascript" },
		{ "txt",   "text/plain" },
		{ "css",   "text/css" },
		{ "map",   "application/json" },
		{ "woff",  "application/font-woff" },
		{ "woff2", "application/font-woff2" },
		{ "ttf",   "application/font-sfnt" },
		{ "svg",   "image/svg+xml" },
		{ "eot",   "application/vnd.ms-fontobject" },
		{ "mp4",   "video/mp4" },
		{ NULL,    NULL }
	};
	const char *content_type = NULL;
	for (size_t i = 0; extensions[i].ext != 0; i++) {
		const size_t len = strlen(extensions[i].ext);
		if (len > path_length)
			continue;
		if (!strncmp(&path[path_length - len], extensions[i].ext, len)) {
			content_type = extensions[i].filetype;
			break;
		}
	}
	return content_type;
}

/* a simple API, it receives a number, increments it and returns the response */
static int send_api_response(eweb_os_t *w, struct eweb_os_hit_args *args, char *path, char *request_body) {
	assert(w);
	UNUSED(request_body);
	char response[4] = { 0 };

	if (args->form_value_counter == 1 && !strncmp(eweb_form_name(args, 0), "counter", strlen(eweb_form_name(args, 0)))) {
		int c = atoi(eweb_form_value(args, 0));
		if (c > 99 || c < 0)
			c = 0;
		snprintf(response, sizeof response, "%d", ++c);
		return eweb_ok_200(w, args, "\nContent-Type: text/plain", response, path);
	} 
	return eweb_forbidden_403(w, args, "Bad request");
}

static int send_file_response(eweb_os_t *w, struct eweb_os_hit_args *args, char *path, char *request_body, long path_length) {
	assert(w);
	UNUSED(request_body);
	string_t *response = new_string(w, FILE_CHUNK_SIZE);

	if (args->form_value_counter > 0 && eweb_string_matches_value(args->content_type, "application/x-www-form-urlencoded")) {
		string_add(w, response, "<html><head><title>Response Page</title></head>");
		string_add(w, response, "<body><h1>Thanks...</h1>You sent these values<br/><br/>");

		for (long v = 0; v < args->form_value_counter; v++) {
			string_add(w, response, eweb_form_name(args, v));
			string_add(w, response, ": <b>");
			string_add(w, response, eweb_form_value(args, v));
			string_add(w, response, "</b><br/>");
		}

		string_add(w, response, "</body></html>");
		eweb_ok_200(w, args, "\nContent-Type: text/html", string_chars(w, response), path);
		string_free(w, response);
		return EWEB_OK;
	}
	/* work out the file type and check we support it */
	const char *content_type = find_file_type_by_file_extension(path, path_length);
	if (!content_type) {
		string_free(w, response);
		return eweb_forbidden_403(w, args, "file extension type not supported");
	}

	FILE *file = fopen(path, "rb");
	if (!file) {
		string_free(w, response);
		return eweb_not_found_404(w, args, "failed to open file");
	}

	fseek(file, 0, SEEK_END);
	long len = ftell(file);
	fseek(file, 0, SEEK_SET);

	if (len > BIGGEST_FILE) {
		string_free(w, response);
		fclose(file);
		return eweb_forbidden_403(w, args, "files this large are not supported");
	}

	string_add(w, response, "HTTP/1.1 200 OK\nServer: eweb\n");
	string_add(w, response, "Connection: close\n");
	string_add(w, response, "Content-Type: ");
	string_add(w, response, content_type);
	eweb_write_header(w, args->socketfd, string_chars(w, response), len);

	/* send file in blocks */
	while ((len = fread(response->ptr, 1, FILE_CHUNK_SIZE, file)) > 0) {
		if (w->write(w, args->socketfd, response->ptr, len) <= 0)
			break;
	}
	string_free(w, response);
	fclose(file);
	
	w->sleep(w, 1); /* allow socket to drain before closing */
	return EWEB_OK;
}

static int send_response(eweb_os_t *w, struct eweb_os_hit_args *args, char *path, char *request_body, http_verb type) {
	assert(w);
	UNUSED(type);
	const size_t path_length = strlen(path);
	if (!strncmp(&path[path_length - 3], "api", 3))
		return send_api_response(w, args, path, request_body);
	if (path_length == 0)
		return send_file_response(w, args, "index.html", request_body, 10);
	return send_file_response(w, args, path, request_body, path_length);
}

int main(int argc, char **argv) {
	if (argc < 2 || !strncmp(argv[1], "-h", 2)) {
		printf("hint: dweb [port number]\n");
		return EXIT_FAILURE;
	}
	eweb_os_t *w = eweb_os_new(NULL, 0);
	if (!w) {
		printf("os allocation failed\n");
		return EXIT_FAILURE;
	}
	printf("Hit CTRL-C to terminate\n");
	const int r = eweb_server(w, atoi(argv[1]), send_response) == EWEB_OK ?
		EXIT_SUCCESS : EXIT_FAILURE;
	eweb_os_delete(w);
	return r;
}

