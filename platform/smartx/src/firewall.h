#ifndef _FIREWALL_H_
#define _FIREWALL_H_
#ifdef __cplusplus
extern "C"
{
#endif

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

typedef struct Cmds {
    const char *const *set;
    const char *const *unset;
} Cmds;

typedef struct Context_ {
    char local_tun_ip[40];
    char remote_tun_ip[40];
    char ext_if_name[40];
    char if_name[16];
    char wanted_if_name[40];
    char ext_gw_ip[40];

    char server_ip_or_name[40];
    char local_tun_ip6[100];
    char remote_tun_ip6[100];
    char server_ip[40];
} Context;


typedef enum FIREWALL_TYPE { MASTER, CLIENT, PEER } FIRETYPE;

int shell_cmd(const char *substs[][2], const char *args_str, int silent);
char *read_from_shell_command(char *result, size_t sizeof_result, const char *command);
const char *get_default_ext_if_name(void);
const char *get_default_gw_ip(void);
Cmds firewall_rules_cmds( int isserver );
int  firewall_rules(Context *context, int isserver, int set);

Cmds peer_firewall_rules_cmds( );
int  peer_firewall_rules(Context *context, int set);


#ifdef __cplusplus
}
#endif

#endif

