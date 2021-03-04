#ifndef _WEBSVR_H_
#define _WEBSVR_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <sys/unistd.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>

typedef struct _websvr{
    int  mysock_fd;
    unsigned short port;
    char ip[256];
	int (*dispath)(char* func, char* data, char* response);
    int bExit;
}websvr_t;

websvr_t* create_websvr(void* disp, const char* ip, uint64_t port);
void destroy_websvr(websvr_t** p);

#ifdef __cplusplus
}
#endif

#endif


