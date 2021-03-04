#include "osapi.h"
#include <sys/time.h>
#ifdef __linux__
#include <sys/epoll.h>
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#define xendian_swap16(x) (x)

sig_atomic_t * exit_signal_received;

ssize_t safe_write(const int fd, const void *const buf_, size_t count, const int timeout){
    struct pollfd pfd;
    const char *  buf = (const char *) buf_;
    ssize_t       written;
    while (count > (size_t) 0) {
        while ((written = write(fd, buf, count)) < (ssize_t) 0) {
            if (errno == EAGAIN) {
                pfd.fd     = fd;
                pfd.events = POLLOUT;
                if (poll(&pfd, (nfds_t) 1, timeout) <= 0) {
                    return (ssize_t) -1;
                }
            } else if (errno != EINTR || (&exit_signal_received)) {
                return (ssize_t) -1;
            }
        }
        buf += written;
        count -= written;
    }
    return (ssize_t)(buf - (const char *) buf_);
}

ssize_t safe_read(const int fd, void *const buf_, size_t count, const int timeout){
    struct pollfd  pfd;
    unsigned char *buf    = (unsigned char *) buf_;
    ssize_t        readnb = (ssize_t) -1;
    while (readnb != 0 && count > (ssize_t) 0) {
        while ((readnb = read(fd, buf, count)) < (ssize_t) 0) {
            if (errno == EAGAIN) {
                pfd.fd     = fd;
                pfd.events = POLLIN;
                if (poll(&pfd, (nfds_t) 1, timeout) <= 0) {
                    return (ssize_t) -1;
                }
            } else if (errno != EINTR || exit_signal_received) {
                return (ssize_t) -1;
            }
        }
        count -= readnb;
        buf += readnb;
    }
    return (ssize_t)(buf - (unsigned char *) buf_);
}

ssize_t safe_read_partial(const int fd, void *const buf_, const size_t max_count)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              readnb;
    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 && errno == EINTR && !(&exit_signal_received))
        ;
    return readnb;
}

ssize_t safe_write_partial(const int fd, void *const buf_, const size_t max_count)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              writenb;
    while ((writenb = write(fd, buf, max_count)) < (ssize_t) 0 && errno == EINTR && !(&exit_signal_received))
        ;
    return writenb;
}

ssize_t safe_read_limit(const int fd, void *const buf_, const size_t buf_size)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              readnb = 0;
    while ( readnb != buf_size && !(&exit_signal_received) && errno == EINTR ){
        int nred = read(fd, &buf[readnb], buf_size - readnb );
        if( nred > 0 )
            readnb += nred;
        else
            break;
    }
    return readnb;
}

ssize_t safe_write_limit(const int fd, void *const buf_, const size_t buf_size)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              readnb = 0;
    while ( readnb != buf_size && !(&exit_signal_received) && errno == EINTR ){
        int nred = read(fd, &buf[readnb], buf_size - readnb );
        if( nred > 0 )
            readnb += nred;
        else
            break;
    }
    return readnb;
}

#ifdef __linux__
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    struct ifreq ifr;
    int          fd;
    int          err;
    fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "tun module not present. See https://sk.tl/2RdReigK\n");
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", wanted_name == NULL ? "" : wanted_name);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", ifr.ifr_name);
    printf("tun create name:%s\n",if_name);
    return fd;
}
#elif defined(__APPLE__)
int tun_create_by_id(char if_name[IFNAMSIZ], unsigned int id)
{
    struct ctl_info     ci;
    struct sockaddr_ctl sc;
    int                 err;
    int                 fd;
    if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
        return -1;
    }
    memset(&ci, 0, sizeof ci);
    snprintf(ci.ctl_name, sizeof ci.ctl_name, "%s", UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    memset(&sc, 0, sizeof sc);
    sc = (struct sockaddr_ctl){
        .sc_id      = ci.ctl_id,
        .sc_len     = sizeof sc,
        .sc_family  = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_unit    = id + 1,
    };
    if (connect(fd, (struct sockaddr *) &sc, sizeof sc) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "utun%u", id);
    return fd;
}

int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    unsigned int id;
    int          fd;
    if (wanted_name == NULL || *wanted_name == 0) {
        for (id = 0; id < 32; id++) {
            if ((fd = tun_create_by_id(if_name, id)) != -1) {
                return fd;
            }
        }
        return -1;
    }
    if (sscanf(wanted_name, "utun%u", &id) != 1) {
        errno = EINVAL;
        return -1;
    }
    return tun_create_by_id(if_name, id);
}
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    char         path[64];
    unsigned int id;
    int          fd;
    if (wanted_name == NULL || *wanted_name == 0) {
        for (id = 0; id < 32; id++) {
            snprintf(if_name, IFNAMSIZ, "tun%u", id);
            snprintf(path, sizeof path, "/dev/%s", if_name);
            if ((fd = open(path, O_RDWR)) != -1) {
                return fd;
            }
        }
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", wanted_name);
    snprintf(path, sizeof path, "/dev/%s", wanted_name);

    return open(path, O_RDWR);
}
#else
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    char path[64];

    if (wanted_name == NULL) {
        fprintf(stderr,
                "The tunnel device name must be specified on that platform "
                "(try 'tun0')\n");
        errno = EINVAL;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", wanted_name);
    snprintf(path, sizeof path, "/dev/%s", wanted_name);

    printf("tun tun_create name:%s\n",if_name);

    return open(path, O_RDWR);
}
#endif

int tun_close(int fd )
{
    if ( fd < 0 ){
        return -1;
    }
    return close( fd );
}

int tun_set_mtu(const char *if_name, int mtu)
{
    struct ifreq ifr;
    int          fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return -1;
    }
    ifr.ifr_mtu = mtu;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", if_name);
    if (ioctl(fd, SIOCSIFMTU, &ifr) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

#if !defined(__APPLE__) && !defined(__OpenBSD__)
ssize_t tun_read(int fd, void *data, size_t size)
{
    return safe_read_partial(fd, data, size);
}

ssize_t tun_write(int fd, const void *data, size_t size)
{
    return safe_write(fd, data, size, 60);
}
#else
ssize_t tun_read(int fd, void *data, size_t size)
{
    ssize_t  ret;
    uint32_t family;

    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len  = sizeof family,
        },
        {
            .iov_base = data,
            .iov_len  = size,
        },
    };

    ret = readv(fd, iov, 2);
    if (ret <= (ssize_t) 0) {
        return -1;
    }
    if (ret <= (ssize_t) sizeof family) {
        return 0;
    }
    return ret - sizeof family;
}

ssize_t tun_write(int fd, const void *data, size_t size)
{
    uint32_t family;
    ssize_t  ret;

    if (size < 20) {
        return 0;
    }
    switch (*(const uint8_t *) data >> 4) {
    case 4:
        family = htonl(AF_INET);
        break;
    case 6:
        family = htonl(AF_INET6);
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len  = sizeof family,
        },
        {
            .iov_base = (void *) data,
            .iov_len  = size,
        },
    };
    ret = writev(fd, iov, 2);
    if (ret <= (ssize_t) 0) {
        return ret;
    }
    if (ret <= (ssize_t) sizeof family) {
        return 0;
    }
    return ret - sizeof family;
}
#endif

long timeclock(){
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);
	return currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
}

char* iptostr(uint32_t ip){
    static char sz[40]={0};
    unsigned char cip[4] = {0};
    memset(sz,0x00,40);
    memcpy(cip,&ip,4);
    sprintf(sz,"%d.%d.%d.%d",cip[0],cip[1],cip[2],cip[3]);
    return sz;
}

void setnonblocking(int sock){
	int opts;
	opts = fcntl(sock, F_GETFL);
	if(opts < 0) {
		printf("fcntl(sock, GETFL)");
        return;
	}
	opts = opts | O_NONBLOCK;
	if(fcntl(sock, F_SETFL, opts) < 0) {
		printf("fcntl(sock, SETFL, opts)");
	}
}

