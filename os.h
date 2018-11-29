#ifndef OS_H
#define OS_H

#include <stddef.h>

struct eweb_os;
typedef struct eweb_os eweb_os_t;

struct eweb_os {
	void *(*malloc)  (eweb_os_t *w, size_t bytes);            /* malloc equivalent */
	void *(*realloc) (eweb_os_t *w, void *ptr, size_t bytes); /* realloc equivalent */
	void  (*free)    (eweb_os_t *w, void *ptr);               /* free equivalent */

	long (*write)(eweb_os_t *w, int fd, const void *buf, size_t count);
	long (*read)(eweb_os_t *w,  int fd, void *buf, size_t count);
	long (*close)(eweb_os_t *w, int fd);

	long (*open)(eweb_os_t *w, unsigned port);
	long (*accept)(eweb_os_t *w, int listenfd);

	void (*log)(eweb_os_t *w, int error, const char *fmt, ...);
	void (*exit)(eweb_os_t *w, int code);

	long (*init)(eweb_os_t *w);
	long (*deinit)(eweb_os_t *w);

	//int listenfd, acceptfd;

	void *arena;  /* arena we are allocating in, if any */
	void *file;   /* logger output */
	void *tag;    /* user tag */
};

eweb_os_t *eweb_os_new(void);
void eweb_os_delete(eweb_os_t *w);

extern eweb_os_t eweb_os;

#endif
