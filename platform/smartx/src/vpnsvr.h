#ifndef _VPNSVR_H_
#define _VPNSVR_H_
#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <poll.h>
#include <cstl/cmap.h>

typedef struct _vpnsvr{
    int is_server;
    bool bServer;
    int bExit;
	int (*dispath)(uint8_t* func, uint8_t* data, uint8_t* response);
    int mysock_fd;
    int mytun_fd;
    int interface_fd;
    map_t * sock_map;
    struct pollfd fds[3];
    int epfd;
    char ip[40];
    unsigned short port;
    int conn_status;
}vpnsvr_t;

vpnsvr_t* create_vpnsvr(void*disp, int stype, const char* ip, short port);
void destroy_vpnsvr(vpnsvr_t **p);

#ifdef __cplusplus
}
#endif

#endif

