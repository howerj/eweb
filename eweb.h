/****************************************************************************
 ** Released under The MIT License (MIT). This code comes without warranty, **
 ** but if you use it you must provide attribution back to David's Blog     **
 ** at http://www.codehosting.net   See the LICENSE file for more details.  **
 ****************************************************************************/

#ifndef DWEBSVR_H
#define DWEBSVR_H

#include <stddef.h>

#define SINGLE_THREADED (1)
#define MULTI_PROCESS   (2)
#define MULTI_THREADED  (3)

#define ERROR    (42)
#define LOG      (43)

typedef enum {
	EWEB_RT_HTTP_NOT_SUPPORTED_E = 100,
	EWEB_RT_HTTP_GET_E           = 101,
	EWEB_RT_HTTP_POST_E          = 102,
} eweb_http_request_type_e;

typedef int http_verb;
typedef int log_type;

typedef struct {
	char name[50];
	char value[255];
} eweb_http_header_t;

struct eweb_os;
struct hitArgs;
typedef struct eweb_os eweb_os_t;

typedef struct {
	void *(*malloc)  (eweb_os_t *w, size_t bytes);            /* malloc equivalent */
	void *(*realloc) (eweb_os_t *w, void *ptr, size_t bytes); /* realloc equivalent */
	void  (*free)    (eweb_os_t *w, void *ptr);               /* free equivalent */
	void *arena;
} eweb_allocator_t; /**@todo integrate this */

struct eweb_os {
	void *(*malloc)  (eweb_os_t *w, size_t bytes);            /* malloc equivalent */
	void *(*realloc) (eweb_os_t *w, void *ptr, size_t bytes); /* realloc equivalent */
	void  (*free)    (eweb_os_t *w, void *ptr);               /* free equivalent */

	long (*write)(eweb_os_t *w, int fd, const void *buf, size_t count);
	long (*read)(eweb_os_t *w,  int fd, void *buf, size_t count);
	long (*close)(eweb_os_t *w, int fd);

	long (*open)(eweb_os_t *w, unsigned port);
	long (*accept)(eweb_os_t *w, int listenfd);

	long (*sleep)(eweb_os_t *w, unsigned seconds);

	void (*log)(eweb_os_t *w, int error, const char *fmt, ...);
	void (*exit)(eweb_os_t *w, int code);

	long (*init)(eweb_os_t *w);
	long (*deinit)(eweb_os_t *w);

	long (*thread_new)(eweb_os_t *w, struct hitArgs *args);
	long (*thread_exit)(eweb_os_t *w, int code);

	long (*kill)(eweb_os_t *w);

	void *arena;  /* arena we are allocating in, if any */
	void *file;   /* logger output */
	void *tag;    /* user tag */
};

eweb_os_t *eweb_os_new(void);
void eweb_os_delete(eweb_os_t *w);

extern eweb_os_t eweb_os;

/* ---------- Memory allocation helpers ---------- */

void *malloc_or_quit(size_t num_bytes, const char *src_file, int src_line);
void *realloc_or_quit(void *ptr, size_t num_bytes, const char *src_file, int src_line);
void *calloc_or_quit(size_t num, size_t size, const char *src_file, int src_line);

#define mallocx(num_bytes) malloc_or_quit((num_bytes), __FILE__, __LINE__)
#define reallocx(ptr, num_bytes) realloc_or_quit((ptr), (num_bytes), __FILE__, __LINE__)
#define callocx(num, size) calloc_or_quit((num), (size), __FILE__, __LINE__)

typedef struct {
	void *ptr;        /**< pointer to the data */
	long alloc_bytes; /**< number of bytes allocated */
	long used_bytes;  /**< number of bytes used */
	long elem_bytes;  /**< number of bytes per element */
	long chunk_size;  /**< number of elements to increase space by */
} block_t;

typedef block_t string_t;

string_t *new_string(long increments);
void string_add(string_t * s, const char *char_array);
char *string_chars(string_t * s);
void string_free(string_t * s);

/* ---------- End of memory allocation helper stuff ---------- */

typedef struct {
	char *name, *value;
	char *data;
} eweb_form_value_t;

typedef int (*responder_cb_t) (eweb_os_t *w, struct hitArgs * args, char *, char *, http_verb);
typedef void (*logger_cb_t) (log_type, char *, char *, int);

struct hitArgs {
	responder_cb_t responder_function;
	logger_cb_t logger_function;
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

int eweb_server(eweb_os_t *w, int port, responder_cb_t responder_func, logger_cb_t logger_func);
int eweb_server_kill(eweb_os_t *w);
int eweb_write_header(eweb_os_t *w, int socket_fd, const char *head, long content_len);
int eweb_write_html(eweb_os_t *w, int socket_fd, const char *head, const char *html);
int eweb_forbidden_403(eweb_os_t *w, struct hitArgs *args, char *info);
int eweb_notfound_404(eweb_os_t *w, struct hitArgs *args, char *info);
int eweb_ok_200(eweb_os_t *w, struct hitArgs *args, char *custom_headers, char *html, char *path);
int eweb_logger(eweb_os_t *w, log_type type, char *s1, char *s2, int socket_fd);
int eweb_webhit(eweb_os_t *w, struct hitArgs *args);

int eweb_string_matches_value(const char *str, const char *value);
char *eweb_form_value(struct hitArgs *args, long i);
char *eweb_form_name(struct hitArgs *args, long i);
void eweb_url_decode(char *s);
char eweb_decode_char(char c);
eweb_http_header_t eweb_get_header(const char *name, char *request, int max_len);

#define UNUSED(X) ((void)(X))

#endif
