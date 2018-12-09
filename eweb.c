/**@file      eweb.c
 * @license   MIT
 * @copyright 2015-2016 http://www.codehosting.net
 * @copyright 2018      Richard James Howe (Changes) 
 * @brief     A small, portable, embeddable web-server, written in C. The
 * code is heavily based on the 'dweb' web-server available at
 * <http://www.codehosting.net>, specifically
 * <https://codehosting.net/blog/BlogEngine/post/dweb-a-lightweight-portable-webserver-in-C>.
 * It has been modified to abstract out the operating system specific code into
 * a series of callbacks. It is available at <https://github.com/howerj/eweb>. */
#include "eweb.h"
#include <assert.h>
#include <stdio.h> /* needed for snprintf */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INCOMING_REQUEST (4096) /**< maximum bytes to be read from request including headers */
#define FORM_VALUE_BLOCK     (10)   /**< eweb_get_form_values() allocates memory in blocks of this size */
#define READ_BUF_LEN         (255)  /**< eweb_hit() will read data from socket in chunks of this size */

/* Taken from: <https://git.musl-libc.org/cgit/musl/tree/src/string/strtok_r.c> 
 * MIT LICENSED*/
static char *eweb_strtok(char *restrict s, const char *restrict sep, char **restrict p) {
	if (!s && !(s = *p)) 
		return NULL;
	s += strspn(s, sep);
	if (!*s) 
		return *p = 0;
	*p = s + strcspn(s, sep);
	if (**p) 
		*(*p)++ = 0;
	else 
		*p = 0;
	return s;
}

/* assumes a content type of "application/x-www-form-urlencoded" (the default type) */
static int eweb_get_form_values(eweb_os_t *w, struct eweb_os_hit_args *args, char *body) {
	assert(w);
	assert(args);
	assert(body);
	long t = 0, alloc = FORM_VALUE_BLOCK;
	char *saveptr = NULL;
	char *token = eweb_strtok(body, "&", &saveptr);

	args->form_values = mallocx(w, alloc * sizeof(eweb_form_value_t));
	memset(args->form_values, 0, alloc * sizeof(eweb_form_value_t));

	while (token) {
		char *tmp = mallocx(w, strlen(token) + 1);
		strcpy(tmp, token);
		eweb_url_decode(tmp);

		long i = 0;
		const long tlen = strlen(tmp);
		for (i = 0; i < tlen; i++)
			if (tmp[i] == '=')
				break;

		if (i < tlen) {
			if (alloc <= t) {
				const long newsize = alloc + FORM_VALUE_BLOCK;
				args->form_values = reallocx(w, args->form_values, newsize * sizeof(eweb_form_value_t));
				memset(args->form_values + alloc, 0, FORM_VALUE_BLOCK * sizeof(eweb_form_value_t));
				alloc = newsize;
			}

			args->form_values[t].data = mallocx(w, strlen(tmp) + 1);
			strcpy(args->form_values[t].data, tmp);
			args->form_values[t].name = args->form_values[t].data;
			args->form_values[t].value = args->form_values[t].data + 1 + i;
			args->form_values[t++].data[i] = 0;
		}

		token = eweb_strtok(NULL, "&", &saveptr);
		freex(w, tmp);
	}
	args->form_value_counter = t;
	return EWEB_OK;
}

static int eweb_clear_form_values(eweb_os_t *w, struct eweb_os_hit_args *args) {
	assert(args);
	if (!args->form_values)
		return EWEB_OK;
	for (args->form_value_counter--; args->form_value_counter >= 0; args->form_value_counter--)
		freex(w, args->form_values[args->form_value_counter].data);
	freex(w, args->form_values);
	return EWEB_OK;
}

static int eweb_finish_hit(eweb_os_t *w, struct eweb_os_hit_args *args, int exit_code) {
	assert(args);
	UNUSED(exit_code);
	w->close(w, args->socketfd);
	if (args->buffer)
		string_free(w, args->buffer);
	if (args->headers)
		freex(w, args->headers);
	eweb_clear_form_values(w, args);
	if (args->content_type)
		freex(w, args->content_type);
	freex(w, args);
	w->thread_exit(w, exit_code);
	return EWEB_OK;
}

/* writes the given headers and sets the Content-Length */
int eweb_write_header(eweb_os_t *w, const int socket_fd, const char *head, long content_len) {
	assert(w);
	assert(head);
	string_t *header = new_string(w, 255);
	string_add(w, header, head);
	string_add(w, header, "\nContent-Length: ");
	char cl[64+1] = { 0 };
	snprintf(cl, sizeof(cl), "%ld", content_len);
	string_add(w, header, cl);
	string_add(w, header, "\r\n\r\n");
	w->write(w, socket_fd, string_chars(w, header), header->used_bytes - 1);
	string_free(w, header);
	return EWEB_OK;
}

int eweb_write_html(eweb_os_t *w, const int socket_fd, const char *head, const char *html) {
	assert(w);
	assert(head);
	assert(html);
	const long r = eweb_write_header(w, socket_fd, head, strlen(html));
	if (r != EWEB_OK)
		return r;
	w->write(w, socket_fd, html, strlen(html));
	return EWEB_OK;
}

int eweb_forbidden_403(eweb_os_t *w, struct eweb_os_hit_args *args, const char *info) {
	assert(args);
	assert(info);
	const int r = eweb_write_html(w, args->socketfd,
		"HTTP/1.1 403 Forbidden\nServer: eweb\nConnection: close\nContent-Type: text/html",
		"<html><head>\n<title>403 Forbidden</title>\n"
		"</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple webserver.\n</body>"
		"</html>");
	w->log(w, LOG, "403 FORBIDDEN: %s/%d", info, args->socketfd);
	return r;
}

int eweb_not_found_404(eweb_os_t *w, struct eweb_os_hit_args *args, const char *info) {
	assert(args);
	assert(info);
	const int r = eweb_write_html(w, args->socketfd,
		"HTTP/1.1 404 Not Found\nServer: eweb\nConnection: close\nContent-Type: text/html",
		"<html><head>\n<title>404 Not Found</title>\n"
		"</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>");
	w->log(w, LOG, "403 NOT FOUND: %s/%d", info, args->socketfd);
	return r;
}

int eweb_ok_200(eweb_os_t *w, struct eweb_os_hit_args *args, char *custom_headers, char *html, char *path) {
	assert(w);
	string_t *headers = new_string(w, 255);
	string_add(w, headers, "HTTP/1.1 200 OK\nServer: eweb\nCache-Control: no-cache\nPragma: no-cache");
	if (!custom_headers)
		string_add(w, headers, custom_headers);
	eweb_write_html(w, args->socketfd, string_chars(w, headers), html);
	string_free(w, headers);
	w->log(w, LOG, "200 OK: %s/%d", path, args->socketfd);
	return EWEB_OK;
}

eweb_http_header_t eweb_get_header(const char *name, const char *request, int max_len) {
	assert(name);
	assert(request);
	eweb_http_header_t retval;
	memset(&retval, 0, sizeof retval);
	size_t x = 0;
	char *ptr = strstr(request, name);
	char *end = ptr + max_len;
	strncpy(retval.name, name, sizeof(retval.name) - 1);
	retval.name[sizeof(retval.name) - 1] = 0;

	if (!ptr) {
		retval.value[0] = 0;
		return retval;
	}

	while (*ptr++ != ':' && ptr <= end) ;
	while (isblank(*++ptr) && ptr <= end) ;
	while (x < (sizeof(retval.value) - 1) && *ptr != '\r' && *ptr != '\n' && ptr <= end)
		retval.value[x++] = *ptr++;
	retval.value[x] = 0;
	return retval;
}

static long eweb_get_body_start(const char *request) { /* return the starting index of the request body, or end of the HTTP headers */
	assert(request);
	const char *ptr = strstr(request, "\r\n\r\n");
	return !ptr ? -1 : (ptr + 4) - request;
}

static http_verb eweb_request_type(const char *request) {
	assert(request);
	if (strncmp(request, "GET ", 4) == 0 || strncmp(request, "get ", 4) == 0)
		return EWEB_RT_HTTP_GET_E;
	if (strncmp(request, "POST ", 5) == 0 || strncmp(request, "post ", 5) == 0)
		return EWEB_RT_HTTP_POST_E;
	return EWEB_RT_HTTP_NOT_SUPPORTED_E;
}

int eweb_hit(eweb_os_t *w, struct eweb_os_hit_args *args) {
	assert(w);
	assert(args);

	long i = 0, body_size = 0, request_size = 0;
	char buf[READ_BUF_LEN + 1] = { 0 };
	args->buffer = new_string(w, READ_BUF_LEN);

	/* We need to read the HTTP headers first so loop until we receive "\r\n\r\n" */
	while (eweb_get_body_start(string_chars(w, args->buffer)) < 0 && args->buffer->used_bytes <= MAX_INCOMING_REQUEST) {
		memset(buf, 0, READ_BUF_LEN + 1);
		request_size += w->read(w, args->socketfd, buf, READ_BUF_LEN);
		string_add(w, args->buffer, buf);
		if (buf[0] == 0)
			break;
	}

	if (request_size == 0) {
		eweb_finish_hit(w, args, 3);
		return EWEB_OK;
	}

	eweb_http_header_t content_length = eweb_get_header("Content-Length", string_chars(w, args->buffer), args->buffer->used_bytes);
	args->content_length   = atol(content_length.value);
	const long body_start  = eweb_get_body_start(string_chars(w, args->buffer));
	const long headers_end = body_start - 4;

	if (headers_end > 0) {
		args->headers = mallocx(w, headers_end + 1);
		strncpy(args->headers, string_chars(w, args->buffer), headers_end);
		args->headers[headers_end] = 0;
	} else {
		args->headers = mallocx(w, 1);
		args->headers[0] = 0;
	}

	if (body_start >= 0)
		body_size = request_size - body_start;

	/* safari seems to send the headers, and then the body slightly later */
	while (body_size < args->content_length && args->buffer->used_bytes <= MAX_INCOMING_REQUEST) {
		memset(buf, 0, READ_BUF_LEN + 1);
		i = w->read(w, args->socketfd, buf, READ_BUF_LEN);
		if (i > 0) {
			request_size += i;
			string_add(w, args->buffer, buf);
			body_size = request_size - body_start;
		} else {
			/* stop looping if we cannot read any more bytes */
			break;
		}
	}

	if (request_size <= 0) { /* cannot read request, so we'll stop */
		eweb_forbidden_403(w, args, "failed to read http request");
		eweb_finish_hit(w, args, 3);
		return EWEB_OK;
	}

	w->log(w, LOG, "request: %s/%ld", string_chars(w, args->buffer), args->hit);

	const http_verb type = eweb_request_type(string_chars(w, args->buffer));
	if (type == EWEB_RT_HTTP_NOT_SUPPORTED_E) {
		eweb_forbidden_403(w, args, "Only simple GET and POST operations are supported");
		eweb_finish_hit(w, args, 3);
		return EWEB_OK;
	}
	/* get a pointer to the request body (or NULL if it's not there) */
	char *body = (type == EWEB_RT_HTTP_GET_E) ? NULL : (char*)args->buffer->ptr + eweb_get_body_start(string_chars(w, args->buffer));

	/* the request will be "GET [URL] " or "POST [URL] " followed by other details
	we will terminate after the second space, to ignore everything else */
	for (i = (type == EWEB_RT_HTTP_GET_E) ? 4 : 5; i < args->buffer->used_bytes; i++) {
		if (string_chars(w, args->buffer)[i] == ' ') {
			string_chars(w, args->buffer)[i] = 0;	/* second space, terminate string here */
			break;
		}
	}

	long j = (type == EWEB_RT_HTTP_GET_E) ? 4 : 5;

	/* check for an absolute directory */
	if (string_chars(w, args->buffer)[j + 1] == '/') {
		eweb_forbidden_403(w, args, "Absolute paths are not permitted");
		eweb_finish_hit(w, args, 3);
		return EWEB_OK;
	}

	for (; j < i - 1; j++) {
		/* check for any parent directory use */
		if (string_chars(w, args->buffer)[j] == '.' && string_chars(w, args->buffer)[j + 1] == '.') {
			eweb_forbidden_403(w, args, "Parent paths (..) are not permitted");
			eweb_finish_hit(w, args, 3);
			return EWEB_OK;
		}
	}

	eweb_http_header_t ctype = eweb_get_header("Content-Type", args->headers, strlen(args->headers));
	j = strlen(ctype.value);
	if (j > 0) {
		args->content_type = mallocx(w, j + 1);
		strncpy(args->content_type, ctype.value, j);
		if (eweb_string_matches_value(args->content_type, "application/x-www-form-urlencoded"))
			eweb_get_form_values(w, args, body);
	} else {
		args->content_type = mallocx(w, 1);
		args->content_type[0] = 0;
	}

	/* call the "responder function" which has been provided to do the rest */
	args->responder_function(w, args, string_chars(w, args->buffer) + ((type == EWEB_RT_HTTP_GET_E) ? 5 : 6), body, type);
	eweb_finish_hit(w, args, 1);
	return EWEB_OK;
}

int eweb_server_kill(eweb_os_t *w) {
	assert(w);
	return w->kill(w);
}

int eweb_server(eweb_os_t *w, int port, responder_cb_t responder_func) {
	assert(w);

	w->log(w, LOG, "eweb server initialized");
	if (w->init(w) < 0) {
		w->log(w, ERROR, "initialization failed");
		return EWEB_ERROR;
	}

	const int listenfd = w->open(w, port);
	if (listenfd < 0) {
		w->log(w, ERROR, "open failed");
		return EWEB_ERROR;
	}

	for (int hit = 1;; hit++) {
		const int socketfd = w->accept(w, listenfd);
		if (socketfd < 0) {
			/*if (!doing_shutdown) */
			w->log(w, ERROR, "accept failed");
			continue;
		}

		struct eweb_os_hit_args *args = mallocx(w, sizeof(struct eweb_os_hit_args));
		memset(args, 0, sizeof *args);
		args->hit = hit;
		args->socketfd = socketfd;
		args->listenfd = listenfd;
		args->responder_function = responder_func;
		args->w = w;

		const long rval = w->thread_new(w, args);
		if (rval != EWEB_OK) {
			w->log(w, ERROR, "thread new failed");
			continue;
		}
	}
	return EWEB_OK;
}

/* The same algorithm as found here:
 <http://spskhokhar.blogspot.co.uk/2012/09/url-decode-http-query-string.html> */
void eweb_url_decode(char *s) {
	assert(s);
	const size_t len = strlen(s);
	char s_copy[len + 1]; /**@todo replace with allocation */
	char *ptr = s_copy;
	memset(s_copy, 0, sizeof(s_copy));

	for (size_t i = 0; i < len; i++) {
		if (s[i] == '+') {
			*ptr++ = ' ';
		} else if ((s[i] != '%') || (!isxdigit(s[i + 1]) || !isxdigit(s[i + 2]))) {
			*ptr++ = s[i];
		} else {
			*ptr++ = ((eweb_decode_char(s[i + 1]) << 4) | eweb_decode_char(s[i + 2]));
			i += 2;
		}
	}
	*ptr = 0;
	strcpy(s, s_copy);
}

char eweb_decode_char(char c) {
	c = tolower(c);
	return c <= '9' ? c - '0' : c - 'a' + 10;
}

char *eweb_form_value(struct eweb_os_hit_args *args, const long i) {
	assert(args);
	if (i >= args->form_value_counter || i < 0)
		return NULL;
	return args->form_values[i].value;
}

char *eweb_form_name(struct eweb_os_hit_args *args, const long i) {
	assert(args);
	if (i >= args->form_value_counter || i < 0)
		return NULL;
	return args->form_values[i].name;
}

int eweb_string_matches_value(const char *str, const char *value) {
	if (!str || !value)
		return 0;
	return strncmp(str, value, strlen(value)) == 0;
}

/* ---------- Memory allocation helpers ---------- */

/**@todo these memory allocation helpers should take a pointer to
 * eweb_allocator_t and not eweb_os_t */
static inline int bcreate(eweb_os_t *w, block_t *b, const long elem_size, const long inc) {
	assert(b);
	b->elem_bytes = elem_size;
	b->chunk_size = inc;
	b->ptr = callocx(w, b->chunk_size, b->elem_bytes);
	b->alloc_bytes = b->chunk_size * b->elem_bytes;
	b->used_bytes = 0;
	return EWEB_OK;
}

static int badd(eweb_os_t *w, block_t *b, const void *data, long len) {
	assert(b);
	assert(data);
	if ((b->alloc_bytes - b->used_bytes) < len) {
		while (b->alloc_bytes - b->used_bytes < len)
			b->alloc_bytes += (b->chunk_size * b->elem_bytes);
		b->ptr = reallocx(w, b->ptr, b->alloc_bytes);
	}
	memcpy((char*)b->ptr + b->used_bytes, data, len);
	b->used_bytes += len;
	memset((char*)b->ptr + b->used_bytes, 0, b->alloc_bytes - b->used_bytes);
	return EWEB_OK;
}

static void bfree(eweb_os_t *w, block_t *b) {
	assert(w);
	if (!b)
		return;
	freex(w, b->ptr);
	b->used_bytes = 0;
	b->alloc_bytes = 0;
}

string_t *new_string(eweb_os_t *w, long increments) {
	string_t *s = mallocx(w, sizeof(string_t));
	bcreate(w, s, 1, increments);
	badd(w, s, "\0", 1);
	return s;
}

string_t *string_add(eweb_os_t *w, string_t * s, const char *char_array) {
	assert(s);
	assert(char_array);
	s->used_bytes--;
	badd(w, s, char_array, strlen(char_array) + 1);
	return s;
}

char *string_chars(eweb_os_t *w, string_t * s) {
	assert(s);
	UNUSED(w);
	return s->ptr;
}

void string_free(eweb_os_t *w, string_t * s) {
	assert(w);
	bfree(w, s);
	freex(w, s);
}

/* ---------- End of memory allocation helpers ---------- */
