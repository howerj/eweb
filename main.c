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

#define DEFAULT_PORT    (8080)
#define FILE_CHUNK_SIZE (1024)
#define BIGGEST_FILE    (100l * 1024l * 1024l)

typedef struct {
	const char *arg;   /**< parsed argument */
	int error,   /**< turn error reporting on/off */
	    index,   /**< index into argument list */
	    option,  /**< parsed option */
	    reset;   /**< set to reset */
	const char *place; /**< internal use: scanner position */
	int  init;   /**< internal use: initialized or not */
} eweb_getopt_t;     /**< getopt clone */

/* Adapted from: <https://stackoverflow.com/questions/10404448> */
static int eweb_getopt(eweb_getopt_t *opt, const int argc, char *const argv[], const char *fmt) {
	assert(opt);
	assert(fmt);
	assert(argv);
	enum { BADARG_E = ':', BADCH_E = '?' };
	static const char *string_empty = "";

	if (!(opt->init)) {
		opt->place = string_empty; /* option letter processing */
		opt->init  = 1;
		opt->index = 1;
	}

	if (opt->reset || !*opt->place) { /* update scanning pointer */
		opt->reset = 0;
		if (opt->index >= argc || *(opt->place = argv[opt->index]) != '-') {
			opt->place = string_empty;
			return -1;
		}
		if (opt->place[1] && *++opt->place == '-') { /* found "--" */
			opt->index++;
			opt->place = string_empty;
			return -1;
		}
	}

	const char *oli; /* option letter list index */
	if ((opt->option = *opt->place++) == ':' || !(oli = strchr(fmt, opt->option))) { /* option letter okay? */
		 /* if the user didn't specify '-' as an option, assume it means -1.  */
		if (opt->option == '-')
			return -1;
		if (!*opt->place)
			opt->index++;
		if (opt->error && *fmt != ':')
			fprintf(stderr, "illegal option -- %c\n", opt->option);
		return BADCH_E;
	}

	if (*++oli != ':') { /* don't need argument */
		opt->arg = NULL;
		if (!*opt->place)
			opt->index++;
	} else {  /* need an argument */
		if (*opt->place) { /* no white space */
			opt->arg = opt->place;
		} else if (argc <= ++opt->index) { /* no arg */
			opt->place = string_empty;
			if (*fmt == ':')
				return BADARG_E;
			if (opt->error)
				fprintf(stderr, "option requires an argument -- %c\n", opt->option);
			return BADCH_E;
		} else	{ /* white space */
			opt->arg = argv[opt->index];
		}
		opt->place = string_empty;
		opt->index++;
	}
	return opt->option; /* dump back option letter */
}

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
static int send_api_response(eweb_os_t *w, eweb_os_hit_args_t *args, const char *path, const char *request_body) {
	assert(w);
	UNUSED(request_body);
	if (args->form_value_counter == 1 && !strncmp(eweb_form_name(args, 0), "counter", strlen(eweb_form_name(args, 0)))) {
		char response[4] = { 0 };
		int c = atoi(eweb_form_value(args, 0));
		if (c > 99 || c < 0)
			c = 0;
		snprintf(response, sizeof response, "%d", ++c);
		return eweb_ok_200(w, args, "\nContent-Type: text/plain", response, path);
	}
	return eweb_forbidden_403(w, args, "Bad request");
}

static int send_file_response(eweb_os_t *w, eweb_os_hit_args_t *args, const char *path, const char *request_body, long path_length) {
	assert(w);
	UNUSED(request_body);
	FILE *file = NULL;
	string_t *response = new_string(w, FILE_CHUNK_SIZE);
	if (!response)
		goto fail;

	if (args->form_value_counter > 0 && eweb_string_matches_value(args->content_type, "application/x-www-form-urlencoded")) {
		if (!string_add(w, response, "<!DOCTYPE html>\n<html><head><title>Response Page</title></head>"))
			goto fail;
		if (!string_add(w, response, "<body><h1>Thanks...</h1>You sent these values<br/><br/>"))
			goto fail;

		for (long v = 0; v < args->form_value_counter; v++) {
			if (!string_add(w, response, eweb_form_name(args, v)))
				goto fail;
			if (!string_add(w, response, ": <b>"))
				goto fail;
			if (!string_add(w, response, eweb_form_value(args, v)))
				goto fail;
			if (!string_add(w, response, "</b><br/>"))
				goto fail;
		}

		if (!string_add(w, response, "</body></html>"))
			goto fail;
		const int r = eweb_ok_200(w, args, "\nContent-Type: text/html", string_chars(w, response), path);
		string_free(w, response);
		return r;
	}
	/* work out the file type and check we support it */
	const char *content_type = find_file_type_by_file_extension(path, path_length);
	if (!content_type) {
		string_free(w, response);
		return eweb_forbidden_403(w, args, "file extension type not supported");
	}

	file = fopen(path, "rb");
	if (!file) {
		string_free(w, response);
		return eweb_not_found_404(w, args, "failed to open file");
	}

	const int r1 = fseek(file, 0, SEEK_END);
	long len = ftell(file);
	const int r2 = fseek(file, 0, SEEK_SET);
	if (r1 == -1 || r2 == -1 || len == -1) {
		string_free(w, response);
		fclose(file);
		return eweb_forbidden_403(w, args, "seek/tell failed");
	}

	if (len > BIGGEST_FILE) {
		string_free(w, response);
		fclose(file);
		return eweb_forbidden_403(w, args, "files this large are not supported");
	}

	if (!string_add(w, response, "HTTP/1.1 200 OK\nServer: eweb\n"))
		goto fail;
	if (!string_add(w, response, "Connection: close\n"))
		goto fail;
	if (!string_add(w, response, "Content-Type: "))
		goto fail;
	if (!string_add(w, response, content_type))
		goto fail;
	if (eweb_write_header(w, args->socketfd, string_chars(w, response), len) != EWEB_OK)
		goto fail;

	/* send file in blocks */
	while ((len = fread(response->ptr, 1, FILE_CHUNK_SIZE, file)) > 0) {
		if (w->write(w, args->socketfd, response->ptr, len) <= 0)
			break;
	}
	string_free(w, response);
	fclose(file);

	w->sleep(w, 1); /* allow socket to drain before closing */
	return EWEB_OK;
fail:
	if (file)
		fclose(file);
	string_free(w, response);
	return EWEB_ERROR;
}

static int send_response(eweb_os_t *w, eweb_os_hit_args_t *args, const char *path, const char *request_body, http_verb type) {
	assert(w);
	assert(path);
	UNUSED(type);
	const size_t path_length = strlen(path);
	if (!strncmp(&path[path_length - 3], "api", 3))
		return send_api_response(w, args, path, request_body);
	if (path_length == 0)
		return send_file_response(w, args, "index.html", request_body, 10);
	return send_file_response(w, args, path, request_body, path_length);
}

static int help(const char *arg0) {
	assert(arg0);
	FILE *output = stdout;
	fprintf(output, "Usage: %s [-h] [-p port-number] [-m mode]\n", arg0);
	static const char *m = "\n\
eweb - an embeddable web-server\n\n\
git:       https://github.com/hower/eweb\n\
license:   MIT\n\
copyright: 2015-2016 http://www.codehosting.net\n\
           2018      Richard James Howe\n\
           (see project repo for more details)\n\
\n\
Options:\n\n\
\t-h,        Print this help message and exit successfully.\n\
\t-p number, Set server port number for server to listen to.\n\
\t-m mode,   Set server thread management mode.\n\
\n\
This is a demonstration program for a tiny, embeddable web-server. It\n\
is not a fully featured web-server but is designed to be tiny and\n\
most importantly portable with platform dependent functionality hidden\n\
within the library.\n\
\n\
Different methods for coping with simultaneous connections can be\n\
selected from with the '-m' flag. Valid modes are 'thread', 'fork'\n\
and 'single'. Your platform may not support all modes.\n\
\n";
	fputs(m, output);
	fprintf(output, "The default port the server listens on is %d.\n\n", DEFAULT_PORT);
	fprintf(output, "This program returns %d on success, and %d on failure.\n\n", EXIT_SUCCESS, EXIT_FAILURE);
	return 0;
}

static eweb_threading_mode_e resolve_mode(const char *ms) {
	assert(ms);
	if (!strcmp(ms, "thread"))
		return EWEB_TM_MULTI_THREADS_E;
	if (!strcmp(ms, "fork"))
		return EWEB_TM_MULTI_PROCESS_E;
	if (!strcmp(ms, "single"))
		return EWEB_TM_SINGLE_THREAD_E;
	fprintf(stdout, "unknown mode: %s (selecting default)\n", ms);
	return 0; // auto
}

int main(int argc, char **argv) {
	eweb_getopt_t opt = { .init = 0, .error = 1 };
	int ch = -1;
	unsigned port = 8080;
	eweb_threading_mode_e mode = EWEB_TM_MULTI_THREADS_E;
	while ((ch = eweb_getopt(&opt, argc, argv, "hp:m:")) != -1) {
		switch (ch) {
		case 'h': return help(argv[0]); break;
		case 'p': port = atoi(opt.arg); break;
		case 'm': mode = resolve_mode(opt.arg); break;
		default:
			  help(argv[0]);
			  return EXIT_FAILURE;
		}
	}
	if (opt.index != argc) {
		fprintf(stderr, "Unexpected extra arguments\n");
		help(argv[0]);
		return EXIT_FAILURE;
	}
	eweb_os_t *w = eweb_os_new(NULL, mode);
	if (!w) {
		fprintf(stderr, "os allocation failed\n");
		return EXIT_FAILURE;
	}

	w->log(w, EWEB_OK, "hit CTRL-C to terminate");
	const int r = eweb_server(w, port, send_response) == EWEB_OK ? EXIT_SUCCESS : EXIT_FAILURE;
	eweb_os_delete(w);
	return r;
}

