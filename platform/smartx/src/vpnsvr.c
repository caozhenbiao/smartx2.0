#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include "interface.h"
#include "firewall.h"
#include "osapi.h"
#include "vpnsvr.h"

#ifdef __linux__
#include <sys/epoll.h>
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif



#ifdef __NetBSD__
#define DEFAULT_MTU 65535 //1500
#else
#define DEFAULT_MTU 65535 //9000
#endif
 
#define TAG_LEN 6
#define MAX_PACKET_LEN 65500
#define LISTENQ		20
#define SERV_PORT	1959

static const int EPOLLFD_LISTEN = 0, EPOLLFD_VERIFY = 1, EPOLLFD_TUN = 2, EPOLLFD_SOCK= 3;
static const int POLLFD_TUN = 0, POLLFD_CLIENT = 1, POLLFD_COUNT = 2;
static const int INITIAL= 0, CONNECTED = 1,  VERIFYED = 2;

//所有epoll都用该对像
typedef struct event_data {
    int status;
    int sockfd;
    void * cache;
}event_data_t;

typedef struct event_cache {
    unsigned char buf[65500];
    unsigned short pos;
}event_cache_t;

static Context context;
#define MAXEVENTS   50
#ifdef __linux__
struct epoll_event events[MAXEVENTS];
#endif

static void vpnsvr_pthread(void* ptr);

//create vpn service
vpnsvr_t *create_vpnsvr(void* disp, int stype, const char* ip, short port){
    vpnsvr_t* this = (vpnsvr_t *)malloc(sizeof(vpnsvr_t));
    this->is_server = stype;
    strcpy(this->ip, ip );
    this->port = port;
    this->bExit = 0;
	this->mysock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( this->is_server ){
#ifdef __linux__
        struct sockaddr_in serveraddr;
        bzero(&serveraddr, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;   
        serveraddr.sin_addr.s_addr = INADDR_ANY;
        serveraddr.sin_port = htons(port);  
        bind(this->mysock_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
        listen(this->mysock_fd, LISTENQ);

        setnonblocking(this->mysock_fd);
        event_data_t * evt_listen  = (event_data_t *)malloc(sizeof(event_data_t));
        evt_listen->status = EPOLLFD_LISTEN;
        evt_listen->sockfd = this->mysock_fd;

        struct epoll_event ev_listen, ev_tun;
        this->epfd = epoll_create(MAXEVENTS);
        ev_listen.data.ptr = evt_listen;
        ev_listen.events = EPOLLIN;
        epoll_ctl(this->epfd, EPOLL_CTL_ADD, this->mysock_fd, &ev_listen);
        this->sock_map = create_map(int, int);
        map_init(this->sock_map);
#endif 
        //crete tun
        memset(&context, 0x00, sizeof context);
        char wanted_if_name[40]={0};
        this->mytun_fd = tun_create(context.if_name, wanted_if_name);
        if (tun_set_mtu(context.if_name, DEFAULT_MTU) != 0) {
            perror("mtu");
        }
        setnonblocking(this->mytun_fd);
        event_data_t * evt_tun  = (event_data_t *)malloc(sizeof(event_data_t));
        evt_tun->status = EPOLLFD_TUN;
        evt_tun->sockfd = this->mytun_fd;
#ifdef __linux__
        ev_tun.data.ptr = evt_tun;
        ev_tun.events = EPOLLIN;
        epoll_ctl(this->epfd, EPOLL_CTL_ADD, this->mytun_fd, &ev_tun);
 #endif 
        strcpy(context.local_tun_ip,"192.168.192.254");
        strcpy(context.ext_if_name, get_default_ext_if_name());
        printf("ifname:%s\n",  context.if_name);
        printf("wanted_if_name:%s\n", wanted_if_name);
        printf("ext_if_name: [%s]\n", context.ext_if_name);
        printf("local_tun_ip: [%s]\n", context.local_tun_ip);
        printf("remote_tun_ip: [%s]\n", context.remote_tun_ip);
        firewall_rules(&context,1,1);
    }
    pthread_t thread2;
    pthread_create(&thread2, NULL, (void *)&vpnsvr_pthread, (void *)this);
    printf("machine start\n");
    return this;
}

//destory vpn service
void destroy_vpnsvr(vpnsvr_t **p){
    assert(*p!=NULL);
    (*p)->bExit = 1;
    firewall_rules(&context,(*p)->is_server,0);
    map_destroy((*p)->sock_map);
    close((*p)->mysock_fd);
    close((*p)->mytun_fd);
    free(*p);  
    *p = NULL;      
    printf("Delete websvr successfully!\n");  
}

//vpn service connect
void vpnsvr_connect(vpnsvr_t* p){
    assert(p!=NULL);
    struct sockaddr_in serveraddr;
	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;   
	serveraddr.sin_addr.s_addr = inet_addr(p->ip);
	serveraddr.sin_port = htons(p->port);  
    int ret = connect( p->mysock_fd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in));
    p->fds[POLLFD_CLIENT] = (struct pollfd){.fd = p->mysock_fd, .events = POLLIN, .revents = 0};
    static char buf[256] ={0};
    memset( buf, 0x00, sizeof buf );
    int len = verity_request("caozhenbiao","czy20101204",buf);
    uint16_t wnb = safe_write_partial(p->mysock_fd,buf,len);
    if( len == wnb ){
        p->conn_status = CONNECTED;
    }
    printf("client_connect:%d\n",ret);
}

//vpn service accept
void vpnsvr_accept(vpnsvr_t* p){
    assert(p!=NULL);
    struct sockaddr_in clientaddr;
    bzero(&clientaddr, sizeof(clientaddr));
    socklen_t clilen = sizeof(struct sockaddr_in );
    printf("accept connection, fd is %d\n", p->mysock_fd);
    int connfd = accept(p->mysock_fd, (struct sockaddr *)&clientaddr, &clilen);
    if( connfd > 0 ) {
#ifdef __linux__
        struct epoll_event ev_accept;
        event_data_t * evt_accept  = (event_data_t *)malloc(sizeof(event_data_t));
        evt_accept->status = EPOLLFD_VERIFY;
        evt_accept->sockfd = connfd;
        evt_accept->cache  = NULL;
        ev_accept.data.ptr = evt_accept;
        ev_accept.events = EPOLLIN;// | EPOLLRDHUP;
        epoll_ctl(p->epfd, EPOLL_CTL_ADD, connfd, &ev_accept);
        printf("connect from socket:%d  fd:%d, ip:%s\n",connfd,connfd,inet_ntoa(clientaddr.sin_addr));
#endif
    }
}

//vpn service disconnect;
void vpnsvr_disconn(vpnsvr_t*p, int index){
    assert(p!=NULL);
    if( p->is_server ){
#ifdef __linux__
    event_data_t * evt  = (event_data_t *)events[index].data.ptr;
    if( evt ){
        printf("vpn_svr_disconn:%d\n", evt->sockfd);
        struct epoll_event ev_sock;
        ev_sock.events = EPOLLIN;
        epoll_ctl(p->epfd, EPOLL_CTL_DEL, evt->sockfd, &ev_sock); 
        if ( evt->cache ){
            free( evt->cache );
            evt->cache = NULL;
        }
        if( map_size(p->sock_map) ){
            map_iterator_t iterator;
            for(iterator=map_begin(p->sock_map);!iterator_equal(iterator,map_end(p->sock_map));iterator=iterator_next(iterator)){
                if( evt->sockfd == *(int*)pair_second(iterator_get_pointer(iterator))){
                    unsigned int in_ip = *(int*)pair_first(iterator_get_pointer(iterator));
                    Context ntx;
                    memcpy( &ntx, &context, sizeof(Context));
                    sprintf(ntx.remote_tun_ip,"%s",iptostr(in_ip));
                    peer_firewall_rules(&ntx,0);
                    printf("firewall unset ip:%s\n",ntx.remote_tun_ip);
                    map_erase_pos(p->sock_map, iterator);
                    break;
                }
            }
        }
        close(evt->sockfd);
        free( evt );
        events[index].data.ptr = NULL;
    }
#endif
    }else{
        p->conn_status = INITIAL;
        close( p->mysock_fd );
    }
}


//vpn client verify request;
void verify_request( vpnsvr_t* p){
    assert(p!=NULL);
    static unsigned char buf[65535] ={0};
    static int pos = 0;
    int package_one = 0;
    int readnb = -1;
    memset( buf, 0x00, sizeof buf );
    if ((readnb = safe_read_partial(p->mysock_fd, &buf[pos], 9 + MAX_PACKET_LEN - pos)) <= 0) {
        return;
    }
    printf("node_verify 1\n");
    pos += readnb;
    while ( pos >= 9 ) {
        uint16_t binlen = 0;
        memcpy(&binlen, buf, 2);
        uint16_t len = (ssize_t) endian_swap16(binlen);
        int len_with_header = 2 + TAG_LEN + len + 1;
        printf("socket pos:%d len:%d lenwithheader:%d\n", pos, len, len_with_header );
        if (pos < len_with_header ) {
            break;
        }else if( pos == len_with_header ){
            //协议格式检查
            package_one = 1;
            pos = 0;
            break;
        }
        //粘包处理
        if( pos > len_with_header ){
            size_t remaining = pos - len_with_header, i;
            for (i = 0; i < remaining; i++) {
                buf[i] = buf[len_with_header + i];
            }
        }
        pos -= len_with_header;
    }
    if( package_one == 0 ){
        firewall_rules(&context,0,0);
        printf("firewall_rules(&context,0,0)\n");
        return;
    }
    
    //创建TUN
    memset(&context, 0x00, sizeof(Context));
    sprintf(context.local_tun_ip, "%d.%d.%d.%d",buf[8],buf[9],buf[10],buf[11]);
    strcpy(context.remote_tun_ip,"192.168.192.254");
    strcpy(context.server_ip_or_name,p->ip);
    snprintf(context.local_tun_ip6 , 100, "64:ff9b::%s", context.local_tun_ip);
    snprintf(context.remote_tun_ip6, 100, "64:ff9b::%s", context.remote_tun_ip);
    snprintf(context.ext_gw_ip, sizeof context.ext_gw_ip, "%s", get_default_gw_ip());
    strcpy(context.server_ip,p->ip);

    printf("local lanip:%s\n", context.local_tun_ip);
    p->mytun_fd = tun_create(context.if_name, context.wanted_if_name);
    if (p->mytun_fd == -1) {
        perror("error tun device creation\n");
        return;
    }
    printf("Interface: [%s]\n", context.if_name);
    if (tun_set_mtu(context.if_name, DEFAULT_MTU) != 0) {
        perror("mtu");
    }
    printf("ifname:%s\n",  context.if_name);
    printf("wanted_if_name:%s\n", context.wanted_if_name);
    printf("ext_if_name: [%s]\n", context.ext_if_name);
    printf("local_tun_ip: [%s]\n", context.local_tun_ip);
    printf("ext_gw_ip: [%s]\n", context.ext_gw_ip);
    firewall_rules(&context,0,1);
    p->fds[POLLFD_TUN] =(struct pollfd){ .fd = p->mytun_fd, .events = POLLIN, .revents = 0 };
    setnonblocking(p->mysock_fd);
    printf("verify success!\n");
    p->conn_status = VERIFYED;
    pos = 0;
}

//认证处理
void vpnsvr_verify(vpnsvr_t * p, int index){
    printf("node_verify:%d\n",index);
#ifdef __linux__
    unsigned char buf[65535] = {0};
    static int interfacefd = 0;
    event_data_t * evt_sock  = (event_data_t *)events[index].data.ptr;
    //read login info
    int readnb = -1;
    if ((readnb = safe_read_partial(evt_sock->sockfd,buf,sizeof buf)) <= 0) {
        vpnsvr_disconn(p,index);
        return;
    }
    unsigned int lanip  = 0;
    if( verify_user(interfacefd, &lanip, (char*)buf, readnb) == -1  ){
        vpnsvr_disconn(p,index);
        return;
    }
    //response verify info
    int wnb = 0;
    memset( buf, 0x00, 65535);
    size_t plen = lanip_response(lanip, buf);
    if ((wnb = safe_write_partial(evt_sock->sockfd,buf,plen)) <= 0) {
        vpnsvr_disconn(p,index);
        return;
    }
    //update events
    event_cache_t * cach_sock = (event_cache_t*)malloc(sizeof(event_cache_t));
    cach_sock->pos = 0;
    evt_sock->status = EPOLLFD_SOCK;
    evt_sock->cache = cach_sock;
    struct epoll_event ev_sock;
    ev_sock.data.ptr = evt_sock;
    ev_sock.events = EPOLLIN|EPOLLET;
    setnonblocking(evt_sock->sockfd);
    epoll_ctl(p->epfd, EPOLL_CTL_MOD, evt_sock->sockfd, &ev_sock);
    *(int*)map_at(p->sock_map,lanip) = evt_sock->sockfd;
    sprintf(context.remote_tun_ip,"%s",iptostr(lanip));
    printf("lanip:%d socket:%d  ipaddr:%s\n",lanip, evt_sock->sockfd, context.remote_tun_ip);
    peer_firewall_rules(&context,1);
#endif
}

//入站处理 socket
void vpnsvr_inboard(vpnsvr_t* p, int index){
    long n = timeclock();
    if( p->is_server ){
#ifdef __linux__
        event_data_t* evt = (event_data_t *)events[index].data.ptr;
        if (!evt->cache)
            return;
        uint16_t readnb = -1;
        event_cache_t* cache  = (event_cache_t*)evt->cache;
        if((readnb = safe_read_partial(evt->sockfd, &cache->buf[cache->pos],9+MAX_PACKET_LEN-cache->pos))<= 0) {
            vpnsvr_disconn(p,index);
            return;
        }
        cache->pos += readnb;
        while ( cache->pos >= 9 ) {
            uint16_t binlen = 0;
            memcpy(&binlen, cache->buf, 2);
            uint16_t len = endian_swap16(binlen);
            uint16_t len_with_header = 2 + TAG_LEN + len + 1;
            if( cache->pos < len_with_header )
                break;
            unsigned char cs = checksum(&cache->buf[8],len);
            unsigned char cz = cache->buf[len+8];
            if(cs != cz || tun_write(p->mytun_fd,&cache->buf[8],len)!=len) {
                printf("error tun_write len:%d  pos:%d  cs:%d  cz:%d\n", len, cache->pos, cs, cz);
                cache->pos = 0;
                break;
            }
            if( cache->pos > len_with_header ){
                size_t remaining = cache->pos - len_with_header, i;
                for (i = 0; i < remaining; i++) {
                    cache->buf[i] = cache->buf[len_with_header + i];
                }
            }
            cache->pos -= len_with_header;
        }
#endif
    }else{
        static unsigned char buf[65535] ={0};
        static uint16_t pos = 0;
        uint16_t readnb = -1;
        if ((readnb = safe_read_partial(p->mysock_fd, &buf[pos], 9+MAX_PACKET_LEN-pos)) <= 0) {
            return;
        }
        pos += readnb;
        while ( pos >= 9 ) {
            uint16_t binlen = 0;
            memcpy(&binlen, buf, 2);
            uint16_t len = (ssize_t) endian_swap16(binlen);
            int len_with_header = 2 + TAG_LEN + len + 1;
            if (pos < len_with_header ) {
                break;
            }
            if( checksum(&buf[8],len) != buf[len+8] || tun_write(p->mytun_fd,&buf[8],len) != len) {
                printf("len tun_write");
                pos = 0;
                break;
            }
            if( pos > len_with_header ){
                memcpy(buf,&buf[len_with_header],pos-len_with_header);
            }
            pos -= len_with_header;
        }
    }
    long m = timeclock();
    static int ntime2 = 0;
    static int nsum2  = 0;
    ntime2++;
    nsum2+=(m-n);
    printf("inboard_handle usedtime:%d\n",nsum2/ntime2);
}

//出站处理 tun_read
void vpnsvr_outboard(vpnsvr_t* p){
    long n = timeclock();
    static unsigned char data[65500] = {0};
    uint16_t len = tun_read(p->mytun_fd, data, sizeof data);
    if( p->is_server && len > 20 && map_size(p->sock_map)){
        unsigned int in_ip = 0;
        memcpy(&in_ip, &data[16], 4);
        map_iterator_t value = map_find( p->sock_map, in_ip );
        if( iterator_not_equal(value, map_end(p->sock_map)) ){
            int remote_fd = *(int*)pair_second(iterator_get_pointer(value));
            static unsigned char buf[65535] = {0};
            uint16_t plen = tun_datapkg(data,len,buf);
            ssize_t wnb = safe_write_partial(remote_fd,buf,plen);
            if (wnb < (ssize_t)0) {
                printf("safe_write_partial :%ld\n", wnb);
                vpnsvr_disconn(p,remote_fd);
            }
        }
    }else if( !p->is_server && len > 20 ) {
        ip_hdr hdr;
        memcpy( &hdr, data, sizeof(ip_hdr));
        if( hdr.protocol == 0x11 || hdr.protocol == 0x06 ){
            static unsigned char buf[65535] = {0};
            uint16_t plen = tun_datapkg(data, len, buf);
            ssize_t  wnb  = safe_write_partial(p->mysock_fd, buf,plen);  
            //printf("safe_write_partial len:%d wnb:%zd\n", len, plen);
        }
    }
}

//事件处理线程
void vpnsvr_pthread(void* argv){
    vpnsvr_t * vpn = (vpnsvr_t*)argv;
    if( vpn->is_server ){
        while( !vpn->bExit ) {
#ifdef __linux__
            int nfds = epoll_wait(vpn->epfd, events, MAXEVENTS, 500), i;
            for(i = 0; i < nfds; ++i) {
                if( !events[i].data.ptr)continue;
                event_data_t * evt = (event_data_t *)events[i].data.ptr;
                if( events[i].events & EPOLLRDHUP){vpnsvr_disconn(vpn,i);}
                else if(evt->status == EPOLLFD_LISTEN) {vpnsvr_accept(vpn);}
                else if(events[i].events & EPOLLIN && evt->status == EPOLLFD_TUN) {vpnsvr_outboard(vpn);}
                else if(events[i].events & EPOLLIN && evt->status == EPOLLFD_SOCK) {vpnsvr_inboard(vpn,i);}
                else if(events[i].events & EPOLLIN && evt->status == EPOLLFD_VERIFY) {vpnsvr_verify(vpn,i);}
            }
#endif
        }
    }else{
        while(!vpn->bExit){
            int found_fds;
            if ((found_fds = poll(vpn->fds, POLLFD_COUNT, 1500)) == -1) {continue;}
            if( vpn->conn_status == INITIAL ){vpnsvr_connect(vpn);continue;}
            if ((vpn->fds[POLLFD_TUN].revents & POLLERR) || (vpn->fds[POLLFD_TUN].revents & POLLHUP)) {puts("HUP (tun)");return;}
            else if (vpn->fds[POLLFD_TUN].revents & POLLIN) {vpnsvr_outboard(vpn);}
            else if ( vpn->conn_status == VERIFYED && vpn->fds[POLLFD_CLIENT].revents & POLLIN) {vpnsvr_inboard(vpn,-1);}
            else if ( vpn->conn_status == CONNECTED && vpn->fds[POLLFD_CLIENT].revents & POLLIN) {verify_request(vpn);}
        }
    }
    printf("machine stop\n");
}

