/**@file      eweb.c
 * @license   MIT
 * @copyright 2015-2016 http://www.codehosting.net
 * @copyright 2018      Richard James Howe (Changes) 
 * @brief     Operating system specific functionality for the eweb web-server,
 * available at <https://github.com/howerj/eweb>. */

#include "eweb.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/**@todo remove these globals */
/* a global place to store the listening socket descriptor*/
static int listenfd; // @warning Not set!
static volatile sig_atomic_t doing_shutdown = 0;

static long eweb_init(eweb_os_t *w) {
	UNUSED(w);
#ifndef SIGCLD
	signal(SIGCHLD, SIG_IGN);
#else
	signal(SIGCLD, SIG_IGN);
#endif
	signal(SIGHUP,  SIG_IGN); /* ignore terminal hangups */
	signal(SIGPIPE, SIG_IGN); /* ignore broken pipes */
	return 0;
}

static long eweb_log(eweb_os_t *w, int error, const char *fmt, ...) {
	assert(w);
	FILE *output = w->file ? w->file : stderr;
	va_list ap;
	va_start(ap, fmt);
	fprintf(output, "%d: ", error);
	vfprintf(output, fmt, ap);
	fputc('\n', output);
	va_end(ap);
	fflush(output);
	return error;
}

static void inthandler(int sig) {
	if (doing_shutdown == 1)
		return;
	doing_shutdown = 1;
	fputs("web-server shutting down\n", stderr); // !!
	close(listenfd);
	if (sig != SIGUSR1)
		exit(0);
}

static long eweb_kill(eweb_os_t *w) {
	UNUSED(w);
	inthandler(SIGUSR1);
	return EWEB_OK;
}

static long eweb_open(eweb_os_t *w, unsigned port) {
	assert(w);
	struct sockaddr_in serv_addr = { 0 };

	if (port == 0) {
		port = 8080;
		w->log(w->file, EWEB_OK, "using default port (%u)", port);
	}

	errno = 0;
	const long listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		w->log(w, EWEB_ERROR, "socket failed: %s", strerror(errno));
		return -1;
	}

	/* For Linux support, MSG_NOSIGNAL is used: See <http://stackoverflow.com/questions/108183/> */
	int y = 1;
#ifdef SO_NOSIGPIPE
	errno = 0;
	/* use SO_NOSIGPIPE, to ignore any SIGPIPEs */
	if (setsockopt(listenfd, SOL_SOCKET, SO_NOSIGPIPE, &y, sizeof(y)) < 0) {
		w->log(w, EWEB_ERROR, "setsocketopt(SO_NOSIGPIPE) failed: %s", strerror(errno));
		return -1;
	}
	y = 1;
#endif

	errno = 0;
	/* use SO_REUSEADDR, so we can restart the server without waiting */
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) < 0) {
		w->log(w, EWEB_ERROR, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
		return -1;
	}
	/* as soon as listenfd is set, keep a handler so we can close it on exit */
	signal(SIGINT, inthandler);
	signal(SIGTERM, inthandler);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	errno = 0;
	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		w->log(w, EWEB_ERROR, "bind failed: %s", strerror(errno));
		return -1;
	}

	errno = 0;
	if (listen(listenfd, 64) < 0) {
		w->log(w, EWEB_ERROR, "listen failed: %s", strerror(errno));
		return -1;
	}

	return listenfd;
}

static long eweb_accept(eweb_os_t *w, int listenfd) {
	assert(w);
	struct sockaddr_in cli_addr = { 0 };
	if (doing_shutdown)
		return -1;
	socklen_t length = sizeof(cli_addr);
	errno = 0;
	const int socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length);
	if (socketfd < 0) {
		w->log(w, EWEB_ERROR, "accept failed: %s", strerror(errno));
		return socketfd;
	}

	struct timeval timeout = { .tv_sec = 60, .tv_usec = 0 };
	errno = 0;
	if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0) {
		w->log(w, EWEB_ERROR, "setsocketopt(SO_RCVTIMEO) failed: %s", strerror(errno));
		w->close(w, socketfd);
		return -1;
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
	return EWEB_OK;
}

static long eweb_sleep(eweb_os_t *w, unsigned seconds) {
	assert(w);
	UNUSED(w);
	long i = seconds;
	while((i = sleep(i)));
	return EWEB_OK;
}

static long eweb_thread_exit(eweb_os_t *w, int exit_code) {
	assert(w);
	UNUSED(w);
	if (w->threading_mode == EWEB_TM_MULTI_PROCESS_E) {
		w->exit(w, exit_code);
	} else if (w->threading_mode == EWEB_TM_MULTI_THREADS_E) {
		UNUSED(exit_code);
		pthread_exit(NULL);
	} else {
		UNUSED(exit_code);
	}
	return EWEB_OK;
}

static void *eweb_thread_main(void *targs) {
	struct eweb_os_hit_args *args = (struct eweb_os_hit_args *)targs;
	pthread_detach(pthread_self());
	eweb_hit(args->w, args);
	return NULL;
}

static long eweb_thread_new(eweb_os_t *w, struct eweb_os_hit_args *args) {
	assert(w);
	assert(args);
	if (w->threading_mode == EWEB_TM_SINGLE_THREAD_E) { /**@todo allow configurable mode selection */
		return eweb_hit(w, args);
	} else if (w->threading_mode == EWEB_TM_MULTI_PROCESS_E) {
		errno = 0;
		const int pid = fork();
		if (pid < 0)
			return w->log(w, EWEB_ERROR, "failed to fork(): %d", strerror(errno));
		if (pid == 0) { /* child */
			close(args->listenfd);
			return eweb_hit(w, args); /* never returns */
		}
		close(args->socketfd);
	} else if (w->threading_mode == EWEB_TM_MULTI_THREADS_E) {
		pthread_t thread_id; /** ??? */
		if (pthread_create(&thread_id, NULL, eweb_thread_main, args) != 0)
			return w->log(w, EWEB_ERROR, "failed to create thread");
	} else {
		w->log(w, EWEB_ERROR, "invalid threading MODE: %u", w->threading_mode);
		abort();
	}
	return EWEB_OK;
}


static void eweb_os_free(void *arena, void *p) {
	UNUSED(arena);
	free(p);
}

static void *eweb_os_malloc(void *arena, size_t sz) {
	UNUSED(arena);
	return malloc(sz);
}

static void *eweb_os_realloc(void *arena, void *ptr, size_t sz) {
	UNUSED(arena);
	return realloc(ptr, sz);
}

static const eweb_allocator_t eweb_os_default_allocator = {
	.malloc  = eweb_os_malloc,
	.free    = eweb_os_free,
	.realloc = eweb_os_realloc,
	.arena = NULL,
};

const eweb_os_t eweb_os = {
	.allocator   = {
		.malloc  = eweb_os_malloc,
		.free    = eweb_os_free,
		.realloc = eweb_os_realloc,
		.arena = NULL, 
	},
	.open        = eweb_open,
	.close       = eweb_close,
	.read        = eweb_read,
	.write       = eweb_write,
	.accept      = eweb_accept,
	.exit        = eweb_exit,
	.sleep       = eweb_sleep,
	.kill        = eweb_kill,
	.thread_exit = eweb_thread_exit,
	.thread_new  = eweb_thread_new,
	.log         = eweb_log,
	.init        = eweb_init,
	.deinit      = eweb_deint,
	.threading_mode = EWEB_TM_SINGLE_THREAD_E,
};

eweb_os_t *eweb_os_new(eweb_allocator_t *allocator, eweb_threading_mode_e mode) {
	eweb_os_t *w = NULL;
	const eweb_allocator_t *a = allocator ? allocator : &eweb_os_default_allocator;
	w = a->malloc(a->arena, sizeof(*w));
	if (!w)
		return w;
	memset(w, 0, sizeof(*w));
	*w = eweb_os;
	w->file = stderr;
	w->allocator = *a;
	switch (mode) {
	case EWEB_TM_SINGLE_THREAD_E: break;
	case EWEB_TM_MULTI_PROCESS_E: break;
	default: /* fall through */
	case EWEB_TM_MULTI_THREADS_E:
		mode = EWEB_TM_MULTI_THREADS_E;
		break;
	}
	w->threading_mode = mode;
	return w;
}

void eweb_os_delete(eweb_os_t *w) {
	if (!w)
		return;
	eweb_allocator_t allocator = w->allocator;
	allocator.free(allocator.arena, w);
}

