#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "firewall.h"
 
int shell_cmd(const char *substs[][2], const char *args_str, int silent){
    char * args[64];
    char   cmdbuf[4096];
    pid_t  child;
    size_t args_i = 0, cmdbuf_i = 0, args_str_i, i;
    int    c, exit_status, is_space = 1;
    errno = ENOSPC;
    for (args_str_i = 0; (c = args_str[args_str_i]) != 0; args_str_i++) {
        if (isspace((unsigned char) c)) {
            if (!is_space) {
                if (cmdbuf_i >= sizeof cmdbuf) {
                    return -1;
                }
                cmdbuf[cmdbuf_i++] = 0;
            }
            is_space = 1;
            continue;
        }
        if (is_space) {
            if (args_i >= sizeof args / sizeof args[0]) {
                return -1;
            }
            args[args_i++] = &cmdbuf[cmdbuf_i];
        }
        is_space = 0;
        for (i = 0; substs[i][0] != NULL; i++) {
            size_t pat_len = strlen(substs[i][0]), sub_len;
            if (!strncmp(substs[i][0], &args_str[args_str_i], pat_len)) {
                sub_len = strlen(substs[i][1]);
                if (sizeof cmdbuf - cmdbuf_i <= sub_len) {
                    return -1;
                }
                memcpy(&cmdbuf[cmdbuf_i], substs[i][1], sub_len);
                args_str_i += pat_len - 1;
                cmdbuf_i += sub_len;
                break;
            }
        }
        if (substs[i][0] == NULL) {
            if (cmdbuf_i >= sizeof cmdbuf) {
                return -1;
            }
            cmdbuf[cmdbuf_i++] = c;
        }
    }
    if (!is_space) {
        if (cmdbuf_i >= sizeof cmdbuf) {
            return -1;
        }
        cmdbuf[cmdbuf_i++] = 0;
    }
    if (args_i >= sizeof args / sizeof args[0] || args_i == 0) {
        return -1;
    }
    args[args_i] = NULL;
    if ((child = fork()) == (pid_t) -1) {
        return -1;
    } else if (child == (pid_t) 0) {
        if (silent) {
            dup2(dup2(open("/dev/null", O_WRONLY), 2), 1);
        }
        execvp(args[0], args);
        printf("filewall args:%s\n", args[0]);
        _exit(1);
    } else if (waitpid(child, &exit_status, 0) == (pid_t) -1 || !WIFEXITED(exit_status)) {
        return -1;
    }
    return 0;
}

//read shell command
char *read_from_shell_command(char *result, size_t sizeof_result, const char *command){
    FILE *fp;
    char *pnt;
    if ((fp = popen(command, "r")) == NULL) {
        return NULL;
    }
    if (fgets(result, (int) sizeof_result, fp) == NULL) {
        pclose(fp);
        fprintf(stderr, "Command [%s] failed]\n", command);
        return NULL;
    }
    if ((pnt = strrchr(result, '\n')) != NULL) {
        *pnt = 0;
    }
    (void) pclose(fp);
    return *result == 0 ? NULL : result;
}

const char *get_default_gw_ip(void)
{
    static char gw[64];
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__) || defined(__NetBSD__)
    return read_from_shell_command(
        gw, sizeof gw, "route -n get default 2>/dev/null|awk '/gateway:/{print $2;exit}'");
#elif defined(__linux__)
    return read_from_shell_command(gw, sizeof gw,
                                   "ip route show default 2>/dev/null|awk '/default/{print $3}'");
#else
    return NULL;
#endif
}

//get tun name
const char *get_default_ext_if_name(void){
    static char if_name[64];
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
    return read_from_shell_command(if_name, sizeof if_name,"route -n get default 2>/dev/null|awk '/interface:/{print $2;exit}'");
#elif defined(__linux__)
    return read_from_shell_command(if_name, sizeof if_name,"ip route show default 2>/dev/null|awk '/default/{print $5}'");
#else
    return NULL;
#endif
}

//construct firewall rules
Cmds firewall_rules_cmds( int isserver ){
    static const char
    *mset_cmds[] = { "sysctl net.ipv4.ip_forward=1",
        "ip link set dev $IF_NAME up",
        "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
        "iptables -t filter -A FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT",
        "iptables -t filter -A FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",
        NULL },
    *munset_cmds[] = {
        "iptables -t filter -D FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT",
        "iptables -t filter -D FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",
        "iptables -t raw -D PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
        NULL
    },
    *cset_cmds[] = { 
        "ifconfig $IF_NAME $LOCAL_TUN_IP $REMOTE_TUN_IP up",
        "ifconfig $IF_NAME inet6 $LOCAL_TUN_IP6 $REMOTE_TUN_IP6 prefixlen 128 up",
#ifndef NO_DEFAULT_ROUTES
        "route add $EXT_IP $EXT_GW_IP",
        "route add 0/1 $REMOTE_TUN_IP",
        "route add 128/1 $REMOTE_TUN_IP",
        "route add -inet6 -blackhole 0000::/1 $REMOTE_TUN_IP6",
        "route add -inet6 -blackhole 8000::/1 $REMOTE_TUN_IP6",
#endif
        NULL },
    *cunset_cmds[] = {
#ifndef NO_DEFAULT_ROUTES
        "route delete $EXT_IP",
        "route delete 0/1",
        "route delete 128/1",
        "route delete -inet6 0000::/1",
        "route delete -inet6 8000::/1",
#endif
        NULL
    };
    return isserver?(Cmds){mset_cmds, munset_cmds}:(Cmds){cset_cmds,cunset_cmds};
}

//firewal rules set
int firewall_rules(Context *context, int isserver, int set){
    const char *mastersts[][2] = { { "$LOCAL_TUN_IP", context->local_tun_ip },
                                { "$EXT_IF_NAME", context->ext_if_name },
                                { "$IF_NAME", context->if_name },
                                { NULL, NULL } };

    const char *clientsts[][2] = { { "$LOCAL_TUN_IP6", context->local_tun_ip6 },
                                { "$REMOTE_TUN_IP6", context->remote_tun_ip6 },
                                { "$LOCAL_TUN_IP", context->local_tun_ip },
                                { "$REMOTE_TUN_IP", context->remote_tun_ip },
                                { "$EXT_IP", context->server_ip },
                                { "$EXT_IF_NAME", context->ext_if_name },
                                { "$EXT_GW_IP", context->ext_gw_ip },
                                { "$IF_NAME", context->if_name },
                                { NULL, NULL } };

    const char *const *cmds;
    if ((cmds = (set ? firewall_rules_cmds(isserver).set: firewall_rules_cmds(isserver).unset)) == NULL) {
        printf("Routing commands for that operating system have not been added yet.\n");
        return 0;
    }
    size_t i;
    for (i = 0; cmds[i] != NULL; i++) {
        printf("firewall cmds:%s\n",cmds[i]);
        if (shell_cmd( isserver?mastersts:clientsts, cmds[i], 0) != 0) {
            printf("Unable to run [%s]: [%s]\n", cmds[i], strerror(errno));
            return -1;
        }
    }
    return 0;
}

//construct firewall rules
Cmds peer_firewall_rules_cmds(){
    static const char
    *nset_cmds[] ={ "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
        "iptables -t nat -A POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j MASQUERADE",
        NULL },
    *nunset_cmds[] = {
        "iptables -t nat -D POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j MASQUERADE",
        NULL
    };
    return (Cmds){nset_cmds,nunset_cmds};
}

int peer_firewall_rules(Context *context,int set){
    const char *nodests[][2] = { { "$LOCAL_TUN_IP", context->local_tun_ip },
                                { "$EXT_IF_NAME", context->ext_if_name },
                                { "$REMOTE_TUN_IP", context->remote_tun_ip },
                                { "$IF_NAME", context->if_name },
                                { NULL, NULL } };
    const char *const *cmds;
    if ((cmds = (set?peer_firewall_rules_cmds().set:peer_firewall_rules_cmds().unset)) == NULL) {
        printf("Routing commands for that operating system have not been added yet.\n");
        return 0;
    }
    size_t i;
    for (i = 0; cmds[i] != NULL; i++) {
        printf("firewall cmds:%s\n",cmds[i]);
        if (shell_cmd( nodests, cmds[i], 0) != 0) {
            printf("Unable to run [%s]: [%s]\n", cmds[i], strerror(errno));
            return -1;
        }
    }
    return 0;
}

