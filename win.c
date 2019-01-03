/**@file      eweb.c
 * @license   MIT
 * @copyright 2015-2016 http://www.codehosting.net
 * @copyright 2018      Richard James Howe (Changes)
 * @brief     Operating system specific functionality for the eweb web-server,
 * available at <https://github.com/howerj/eweb>. */

#define _WIN32_WINNT 0x0600
#include "eweb.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <direct.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <conio.h>

static bool tcp_stack_initialized = false;

/*#pragma comment(lib, "Ws2_32.lib")*/

/* https://msdn.microsoft.com/en-us/library/ms679351%28v=VS.85%29.aspx
 * https://stackoverflow.com/questions/3400922/how-do-i-retrieve-an-error-string-from-wsagetlasterror */
static void winsock_perror(char *msg) {
	wchar_t *s = NULL;
	int e = WSAGetLastError();
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		       NULL, e,
		       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		       (LPWSTR)&s, 0, NULL);
	//fprintf(stderr, "%s: (%d) %S", msg, e, s);
	fprintf(stderr, "%s: (%d)", msg, e);
	LocalFree(s);
}

static void binary(FILE *f) {
    assert(f);
    setmode(_fileno(f), O_BINARY);
}

static void win_once_init(void) {
	static WSADATA wsaData;
	if (tcp_stack_initialized)
            return;

        binary(stdin);
        binary(stdout);
        binary(stderr);

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                winsock_perror("WSAStartup failed");
                exit(EXIT_FAILURE);
        }
        tcp_stack_initialized = true;
}

static long eweb_init(eweb_os_t *w) {
	UNUSED(w);
	win_once_init();
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

/*static void inthandler(int sig) {
	if (doing_shutdown == 1)
		return;
	doing_shutdown = 1;
	fputs("web-server shutting down\n", stderr); // !!
	closesocket(listenfd);
	if (sig != SIGUSR1)
		exit(0);
}*/

static long eweb_kill(eweb_os_t *w) {
	UNUSED(w);
	//inthandler(SIGUSR1);
	return EWEB_OK;
}

static long eweb_open(eweb_os_t *w, unsigned port) {
	assert(w);
	struct sockaddr_in serv_addr = { 0 };
	assert(port > 0);
	errno = 0;
	const long listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		w->log(w, EWEB_ERROR, "socket failed: %s", strerror(errno));
		return -1;
	}

	int y = 1;
	errno = 0;
	/* use SO_REUSEADDR, so we can restart the server without waiting */
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char*)&y, sizeof(y)) < 0) {
		w->log(w, EWEB_ERROR, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
		return -1;
	}

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
	return closesocket(fd);
}

static long eweb_write(eweb_os_t *w, int fd, const void *buf, size_t count) {
	assert(w);
	UNUSED(w);
	return send(fd, buf, count, 0); // !? Flags
}

static long eweb_read(eweb_os_t *w,  int fd, void *buf, size_t count) {
	assert(w);
	UNUSED(w);
	return recv(fd, buf, count, 0); // !? Flags
}

static void eweb_exit(eweb_os_t *w, int code) {
	assert(w);
	UNUSED(w);
	exit(code);
}

/*static void tcp_stack_cleanup(void)
{
}*/

static long eweb_deint(eweb_os_t *w) {
	assert(w);
	UNUSED(w);
	if (tcp_stack_initialized && WSACleanup() != 0) {
		winsock_perror("WSACleanup() failed");
		exit(EXIT_FAILURE);
	}

	return EWEB_OK;
}

static long eweb_sleep(eweb_os_t *w, unsigned seconds) {
	assert(w);
	UNUSED(w);
	Sleep(seconds * 1000ul);
	return EWEB_OK;
}

static long eweb_thread_exit(eweb_os_t *w, int exit_code) {
	assert(w);
	UNUSED(w);
	if (w->threading_mode == EWEB_TM_MULTI_PROCESS_E) {
		w->exit(w, exit_code);
	} else if (w->threading_mode == EWEB_TM_MULTI_THREADS_E) {
		UNUSED(exit_code);
		ExitThread(exit_code);
	} else {
		UNUSED(exit_code);
	}
	return EWEB_OK;
}

static DWORD WINAPI eweb_thread_main(void *targs) {
	eweb_os_hit_args_t *args = (struct eweb_os_hit_args *)targs;
	//pthread_detach(pthread_self()); // need to join in server thread?
	return eweb_hit(args->w, args);
}

static long eweb_thread_new(eweb_os_t *w, eweb_os_hit_args_t *args) {
	assert(w);
	assert(args);
	if (w->threading_mode == EWEB_TM_SINGLE_THREAD_E) {
		return eweb_hit(w, args);
	} else if (w->threading_mode == EWEB_TM_MULTI_THREADS_E) {
		if (!CreateThread(NULL, 0, eweb_thread_main, args, 0, NULL))
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
	case EWEB_TM_MULTI_PROCESS_E:
		fprintf(stderr, "Warning! Threading, not multi-process, used.\n");
		/* fall-through */
	case EWEB_TM_MULTI_THREADS_E:
		break;
	default:
		fprintf(stderr, "Warning! Single threaded only\n");
		/* fall-through */
	case EWEB_TM_SINGLE_THREAD_E: 
		mode = EWEB_TM_SINGLE_THREAD_E;
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

