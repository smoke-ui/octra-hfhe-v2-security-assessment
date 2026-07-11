#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

static const int fake_fd = 0x5a17;
static _Atomic unsigned getrandom_calls;
static _Atomic unsigned read_calls;

typedef int (*open_fn)(const char *, int, ...);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef int (*close_fn)(int);

static const char *scenario(void) {
    const char *value = getenv("ENTROPY_FAULT_SCENARIO");
    return value == NULL ? "" : value;
}

static int is_scenario(const char *name) {
    return strcmp(scenario(), name) == 0;
}

static ssize_t fill(void *buffer, size_t length, size_t limit) {
    size_t count = length < limit ? length : limit;
    memset(buffer, 0xa5, count);
    return (ssize_t)count;
}

ssize_t getrandom(void *buffer, size_t length, unsigned flags) {
    (void)flags;
    unsigned call = atomic_fetch_add(&getrandom_calls, 1) + 1;
    if (is_scenario("short_getrandom")) {
        size_t limit = length > 1 ? length / 2 : 1;
        return fill(buffer, length, limit);
    }
    if (is_scenario("getrandom_eintr") && call == 1) {
        errno = EINTR;
        return -1;
    }
    if (is_scenario("getrandom_eintr")) return fill(buffer, length, length);
    if (is_scenario("zero_fallback")) return 0;
    errno = ENOSYS;
    return -1;
}

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    int has_mode = (flags & O_CREAT) != 0;
#ifdef O_TMPFILE
    has_mode = has_mode || (flags & O_TMPFILE) == O_TMPFILE;
#endif
    if (has_mode) {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    if (strcmp(path, "/dev/urandom") != 0) {
        open_fn next_open = (open_fn)dlsym(RTLD_NEXT, "open");
        if (next_open == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return has_mode ? next_open(path, flags, mode) : next_open(path, flags);
    }
    if (is_scenario("open_fail")) {
        errno = EACCES;
        return -1;
    }
    return fake_fd;
}

ssize_t read(int fd, void *buffer, size_t length) {
    if (fd != fake_fd) {
        read_fn next_read = (read_fn)dlsym(RTLD_NEXT, "read");
        if (next_read == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return next_read(fd, buffer, length);
    }
    unsigned call = atomic_fetch_add(&read_calls, 1) + 1;
    if (is_scenario("read_eintr") && call == 1) {
        errno = EINTR;
        return -1;
    }
    if (is_scenario("read_eof")) return 0;
    if (is_scenario("read_eio")) {
        errno = EIO;
        return -1;
    }
    if (is_scenario("short_read")) {
        size_t limit = length > 1 ? length / 2 : 1;
        return fill(buffer, length, limit);
    }
    return fill(buffer, length, length);
}

int close(int fd) {
    if (fd != fake_fd) {
        close_fn next_close = (close_fn)dlsym(RTLD_NEXT, "close");
        if (next_close == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return next_close(fd);
    }
    if (is_scenario("close_fail")) {
        errno = EIO;
        return -1;
    }
    return 0;
}
