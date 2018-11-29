#include "eweb.h"
#include "os.h"
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h> // for struct timeval

// a global place to store the listening socket descriptor
/**@todo remove these globals */
static int listenfd;
static volatile sig_atomic_t doing_shutdown = 0;

static long eweb_init(eweb_os_t *w) {
	UNUSED(w);

#ifndef SIGCLD
	signal(SIGCHLD, SIG_IGN);
#else
	signal(SIGCLD, SIG_IGN);
#endif
	signal(SIGHUP, SIG_IGN);	// ignore terminal hangups
	signal(SIGPIPE, SIG_IGN);	// ignore broken pipes

	return 0;
}

static void eweb_free(eweb_os_t *w, void *p) {
	assert(w);
	UNUSED(w);
	free(p);
}

static void *eweb_malloc(eweb_os_t *w, size_t sz) {
	assert(w);
	UNUSED(w);
	return malloc(sz);
}

static void *eweb_realloc(eweb_os_t *w, void *ptr, size_t sz) {
	assert(w);
	UNUSED(w);
	return reallocx(ptr, sz);
}

static void eweb_log(eweb_os_t *w, int error, const char *fmt, ...) {
	assert(w);
	FILE *output = w->file ? w->file : stderr;
	va_list ap;
	va_start(ap, fmt);
	fprintf(output, "%d: ", error);
	vfprintf(output, fmt, ap);
	fputc('\n', output);
	va_end(ap);
}

static void inthandler(int sig) { /**@todo Remove this global nonsense */
	if (doing_shutdown == 1)
		return;
	doing_shutdown = 1;
	fputs("webserver shutting down\n", stderr);
	close(listenfd);
	if (sig != SIGUSR1)
		exit(0);
}

static long eweb_open(eweb_os_t *w, unsigned port) {
	assert(w);
	struct sockaddr_in serv_addr = { 0 };

	if (port == 0) {
		port = 8080;
		w->log(w->file, LOG, "using default port (%u)", port);
	}

	long listenfd = -1;
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		//logger_func(ERROR, "system call", "socket", 0);
		return -1;
	}
	/* For Linux support, MSG_NOSIGNAL is used: See <http://stackoverflow.com/questions/108183/> */

	int y = 1;
#ifdef SO_NOSIGPIPE
	// use SO_NOSIGPIPE, to ignore any SIGPIPEs
	if (setsockopt(listenfd, SOL_SOCKET, SO_NOSIGPIPE, &y, sizeof(y)) < 0) {
		//logger_func(ERROR, "system call", "setsockopt -> SO_NOSIGPIPE", 0);
		return -1;
	}
	y = 1;
#endif

	// use SO_REUSEADDR, so we can restart the server without waiting
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) < 0) {
		//logger_func(ERROR, "system call", "setsockopt -> SO_REUSEADDR", 0);
		return -1;
	}
	/* as soon as listenfd is set, keep a handler so we can close it on exit */
	signal(SIGINT, inthandler);
	signal(SIGTERM, inthandler);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		//logger_func(ERROR, "system call", "bind", 0);
		return -1;
	}

	if (listen(listenfd, 64) < 0) {
		//logger_func(ERROR, "system call", "listen", 0);
		return -1;
	}

	return listenfd;
}

static long eweb_accept(eweb_os_t *w, int listenfd) {
	assert(w);
	struct sockaddr_in cli_addr = { 0 };
	socklen_t length = sizeof(cli_addr);
	const int socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length);
	if (socketfd < 0) {
		//logger_func(ERROR, "system call", "accept", 0);
		return socketfd;
	}

	struct timeval timeout = { .tv_sec = 60, .tv_usec = 0 };
	if (setsockopt (socketfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0) {
		//logger_func(ERROR, "system call", "setsockopt -> SO_RCVTIMEO", 0);
	}
	return socketfd;
}


static long eweb_close(eweb_os_t *w, int fd) {
	assert(w);
	UNUSED(w);
	return close(fd);
}

static long eweb_write(eweb_os_t *w, int fd, const void *buf, size_t count) {
	assert(w);
	UNUSED(w);
#ifndef SO_NOSIGPIPE
	return send(fd, buf, count, MSG_NOSIGNAL);
#else
	return write(fd, buf, count);
#endif
}

static long eweb_read(eweb_os_t *w,  int fd, void *buf, size_t count) {
	assert(w);
	UNUSED(w);
	return read(fd, buf, count);
}

static void eweb_exit(eweb_os_t *w, int code) {
	assert(w);
	UNUSED(w);
	exit(code);
}

static long eweb_deint(eweb_os_t *w) {
	assert(w);
	UNUSED(w);
	return 0;
}

eweb_os_t eweb_os = {
	.arena = NULL,
	.free  = eweb_free,
	.malloc = eweb_malloc,
	.realloc = eweb_realloc,
	.open = eweb_open,
	.close = eweb_close,
	.read = eweb_read,
	.write = eweb_write,
	.accept = eweb_accept,
	.exit = eweb_exit,

	.log = eweb_log,
	.init = eweb_init,
	.deinit = eweb_deint,
};


eweb_os_t *eweb_os_new(void) {
	return NULL;
}

void eweb_os_delete(eweb_os_t *w) {
	UNUSED(w);
}

