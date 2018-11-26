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

#define HTTP_NOT_SUPPORTED  (100)
#define HTTP_GET            (101)
#define HTTP_POST           (102)

#define http_verb int
#define log_type int

struct http_header {
	char name[50];
	char value[255];
};

/* ---------- Memory allocation helper stuff ---------- */

void *malloc_or_quit(size_t num_bytes, const char *src_file, int src_line);
void *realloc_or_quit(void *ptr, size_t num_bytes, const char *src_file, int src_line);
void *calloc_or_quit(size_t num, size_t size, const char *src_file, int src_line);

#define mallocx(num_bytes) malloc_or_quit((num_bytes), __FILE__, __LINE__)
#define reallocx(ptr, num_bytes) realloc_or_quit((ptr), (num_bytes), __FILE__, __LINE__)
#define callocx(num, size) calloc_or_quit((num), (size), __FILE__, __LINE__)

typedef struct {
	void *ptr;       // the pointer to the data
	int alloc_bytes; // the number of bytes allocated
	int used_bytes;  // the number of bytes used
	int elem_bytes;  // the number of bytes per element
	int chunk_size;  // the number of elements to increase space by
} blk;

typedef blk STRING;

STRING *new_string(int increments);
void string_add(STRING * s, char *char_array);
char *string_chars(STRING * s);
void string_free(STRING * s);

/* ---------- End of memory allocation helper stuff ---------- */

typedef struct {
	char *name, *value;
	char *data;
} FORM_VALUE;

struct hitArgs;
typedef void (*responder_cb_t) (struct hitArgs * args, char *, char *, http_verb);
typedef void (*logger_cb_t) (log_type, char *, char *, int);

struct hitArgs {
	responder_cb_t responder_function;
	logger_cb_t logger_function;
	STRING *buffer;
	char *headers;
	char *content_type;
	FORM_VALUE *form_values;
	int content_length;
	int form_value_counter;
	int socketfd;
	int hit;
};

int dwebserver(int port, responder_cb_t responder_func, logger_cb_t logger_func);
void dwebserver_kill(void);

struct http_header get_header(const char *name, char *request, int max_len);

void write_header(int socket_fd, char *head, long content_len);
void write_html(int socket_fd, char *head, char *html);
void forbidden_403(struct hitArgs *args, char *info);
void notfound_404(struct hitArgs *args, char *info);
void ok_200(struct hitArgs *args, char *custom_headers, char *html, char *path);
void logger(log_type type, char *s1, char *s2, int socket_fd);
void webhit(struct hitArgs *args);

char *form_value(struct hitArgs *args, int i);
char *form_name(struct hitArgs *args, int i);
int string_matches_value(char *str, const char *value);

void url_decode(char *s);
char decode_char(char c);

#define UNUSED(X) ((void)(X))

#endif
