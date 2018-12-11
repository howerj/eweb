/**@file      eweb.h
 * @license   MIT
 * @copyright 2015-2016 http://www.codehosting.net
 * @copyright 2018      Richard James Howe (Changes)
 * @brief     A small, portable, embeddable web-server, written in C. The
 * code is heavily based on the 'dweb' web-server available at
 * <http://www.codehosting.net>, specifically
 * <https://codehosting.net/blog/BlogEngine/post/dweb-a-lightweight-portable-webserver-in-C>.
 * It has been modified to abstract out the operating system specific code into
 * a series of callbacks. It is available at <https://github.com/howerj/eweb>. */

#ifndef EWEB_H
#define EWEB_H

#include <stddef.h>

typedef enum {
	/* auto select = 0 */
	EWEB_TM_SINGLE_THREAD_E = 1,
	EWEB_TM_MULTI_PROCESS_E = 2,
	EWEB_TM_MULTI_THREADS_E = 3,
} eweb_threading_mode_e;

typedef enum {
	EWEB_RT_HTTP_NOT_SUPPORTED_E = 100,
	EWEB_RT_HTTP_GET_E           = 101,
	EWEB_RT_HTTP_POST_E          = 102,
} eweb_http_request_type_e;

typedef int http_verb;

typedef struct {
	char name[50];
	char value[255];
} eweb_http_header_t;

struct eweb_os_hit_args;
struct eweb_os;
typedef struct eweb_os eweb_os_t;

typedef struct {
	void *(*malloc)  (void *w, size_t bytes);            /* malloc equivalent */
	void *(*realloc) (void *w, void *ptr, size_t bytes); /* realloc equivalent */
	void  (*free)    (void *w, void *ptr);               /* free equivalent */
	void *arena;
} eweb_allocator_t;

struct eweb_os {
	eweb_allocator_t allocator;

	long (*open)(eweb_os_t *w, unsigned port);  /* open a server socket, bind, set socketopts, -1 on failure */
	long (*accept)(eweb_os_t *w, int listenfd); /* listen and accept a client socket, -1 on failure */
	long (*write)(eweb_os_t *w, int fd, const void *buf, size_t count); /* write to socket */
	long (*read)(eweb_os_t *w,  int fd, void *buf, size_t count);       /* read from socket */
	long (*close)(eweb_os_t *w, int fd);                                /* close socket */

	long (*sleep)(eweb_os_t *w, unsigned seconds); /* sleep for X seconds */

	long (*log)(eweb_os_t *w, int error, const char *fmt, ...); /* log an error message, returns 'error' */
	void (*exit)(eweb_os_t *w, int code); /* exit process */

	long (*init)(eweb_os_t *w);   /* initialize web server */
	long (*deinit)(eweb_os_t *w); /* deinitialize web server */

	long (*thread_new)(eweb_os_t *w, struct eweb_os_hit_args *args); /* create new service thread/process */
	long (*thread_exit)(eweb_os_t *w, int code); /* exit service thread/process */

	long (*kill)(eweb_os_t *w); /* kill web server */

	void *file;   /* logger output handle */
	void *tag;    /* user tag */

	/**@todo hide these better */
	unsigned allocation_error :1; /**< INTERNAL USE ONLY! Has there been an allocation error? */
	unsigned threading_mode   :2; /**< INTERNAL USE ONLY! Threading mode to use */
};

eweb_os_t *eweb_os_new(eweb_allocator_t *a, eweb_threading_mode_e mode);
void eweb_os_delete(eweb_os_t *w);


/* ---------- Memory allocation helpers ---------- */

void *eweb_malloc_or_die(eweb_os_t *w, size_t num_bytes);
void *eweb_realloc_or_die(eweb_os_t *w, void *ptr, size_t num_bytes);
void *eweb_calloc_or_die(eweb_os_t *w, size_t num, size_t size);
void eweb_free(eweb_os_t *w, void *ptr);

typedef struct {
	void *ptr;        /**< pointer to the data */
	long alloc_bytes; /**< number of bytes allocated */
	long used_bytes;  /**< number of bytes used */
	long elem_bytes;  /**< number of bytes per element */
	long chunk_size;  /**< number of elements to increase space by */
} block_t;

typedef block_t string_t;

/**@todo these should use eweb_allocator_t */
string_t *new_string(eweb_os_t *w, long increments);
string_t *string_add(eweb_os_t *w, string_t * s, const char *char_array);
char *string_chars(eweb_os_t *w, string_t * s);
void string_free(eweb_os_t *w, string_t * s);

/* ---------- End of memory allocation helper stuff ---------- */

typedef struct {
	char *name, *value;
	char *data;
} eweb_form_value_t;

typedef int (*responder_cb_t) (eweb_os_t *w, struct eweb_os_hit_args * args, const char *, const char *, http_verb);

struct eweb_os_hit_args {
	responder_cb_t responder_function;
	string_t *buffer;
	char *headers;
	char *content_type;
	eweb_form_value_t *form_values;
	long content_length;
	long form_value_counter;
	long hit;
	int socketfd, listenfd;
	eweb_os_t *w; /**< @todo remove TEMPORARY HACK */
};

enum { EWEB_OK, EWEB_ERROR };

int eweb_server(eweb_os_t *w, unsigned port, responder_cb_t responder_func);
int eweb_server_kill(eweb_os_t *w);
int eweb_write_header(eweb_os_t *w, int socket_fd, const char *head, long content_len);
int eweb_write_html(eweb_os_t *w, int socket_fd, const char *head, const char *html);
int eweb_forbidden_403(eweb_os_t *w, struct eweb_os_hit_args *args, const char *info);
int eweb_not_found_404(eweb_os_t *w, struct eweb_os_hit_args *args, const char *info);
int eweb_ok_200(eweb_os_t *w, struct eweb_os_hit_args *args, const char *custom_headers, const char *html, const char *path);
int eweb_hit(eweb_os_t *w, struct eweb_os_hit_args *args);

int eweb_string_matches_value(const char *str, const char *value);
char *eweb_form_value(struct eweb_os_hit_args *args, long i);
char *eweb_form_name(struct eweb_os_hit_args *args, long i);
int eweb_url_decode(eweb_os_t *w, char *s);
char eweb_decode_char(char c);
eweb_http_header_t eweb_get_header(const char *name, const char *request, const long max_len);

#ifndef UNUSED
#define UNUSED(X) ((void)(X))
#endif

extern const eweb_os_t eweb_os;

#endif
