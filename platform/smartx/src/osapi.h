#ifndef _OSAPI_H_
#define _OSAPI_H_
#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

ssize_t safe_write(const int fd, const void *const buf_, size_t count, const int timeout);
ssize_t safe_read(const int fd, void *const buf_, size_t count, const int timeout);
ssize_t safe_read_limit(const int fd, void *const buf_, const size_t buf_size);
ssize_t safe_write_limit(const int fd, void *const buf_, const size_t buf_size);
ssize_t safe_read_partial(const int fd, void *const buf_, const size_t max_count);
ssize_t safe_write_partial(const int fd, void *const buf_, const size_t max_count);

#ifdef __linux__
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name);
#elif defined(__APPLE__)
int tun_create_by_id(char if_name[IFNAMSIZ], unsigned int id);
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name);
#else
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name);
#endif
int tun_close(int fd );
int tun_set_mtu(const char *if_name, int mtu);

#if !defined(__APPLE__) && !defined(__OpenBSD__)
ssize_t tun_read(int fd, void *data, size_t size);
ssize_t tun_write(int fd, const void *data, size_t size);
#else
ssize_t tun_read(int fd, void *data, size_t size);
ssize_t tun_write(int fd, const void *data, size_t size);
#endif

long timeclock();
char* iptostr(uint32_t ip);
void setnonblocking(int sock);

#ifdef __cplusplus
}
#endif

#endif

