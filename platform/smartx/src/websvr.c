#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include "websvr.h"
 
#ifdef __linux__
#include <sys/epoll.h>
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#define MAX_BUF_SIZE 65535
#define MAX_CLIENT   50

static websvr_t *self = NULL;

int fdarray[MAX_CLIENT];

static void workthread( void* ptr);

websvr_t *create_websvr(void* disp, const char* ip, uint64_t port){
    websvr_t* this = (websvr_t *)malloc(sizeof(websvr_t));  
    this->dispath = disp;
	strcpy(this->ip,ip);
	this->port = port;
	this->bExit  = 0;
	struct sockaddr_in myaddr;
	myaddr.sin_family = AF_INET;
	//myaddr.sin_addr.s_addr = inet_addr( this->mysvrip );
	myaddr.sin_addr.s_addr = INADDR_ANY;
	myaddr.sin_port = htons( this->port );
	this->mysock_fd = socket( AF_INET, SOCK_STREAM, 0 );
	int ibind = bind( this->mysock_fd, (struct sockaddr*)&myaddr, sizeof(struct sockaddr_in));
	if( ibind != 0 ){
		printf("websvr bind socket error! addr=%s:%d\n",this->ip,this->port);
	}
	int ilisten = listen(this->mysock_fd, 50);  
	if( ilisten != 0  ){
		printf("websvr listen error!\n");
	}
	pthread_t theard1;
    pthread_create(&theard1, NULL, (void *)&workthread, (void *)this);
    return self;  
}  

void destroy_websvr(websvr_t **p){
    if (*p != NULL){
		(*p)->bExit =1;
		close((*p)->mysock_fd);
        free(*p);  
        *p = NULL;  
        printf("Delete websvr successfully!\n");  
    }  
} 

int16_t send_pkg(int sock, void* buf, uint16_t size){
	int16_t sendlen = 0;
	int16_t sent = 0;
	for( sent=0,sendlen=0;sendlen<size; sendlen+=sent ){
		sent = send( sock, (char*)buf+sendlen, size-sendlen, 0);
		if( sent <= 0 )
			break;
	}
	return sent;
}
 
char * getContent(const char* t){
	static char* contentType;
	if( strcmp(t,"png") == 0 )
		strcpy(contentType,"image/png");
	else if(strcmp(t,"jpeg")==0 || strcmp(t,"jpg")==0)
		strcpy(contentType,"image/jpeg");
	else if(strcmp(t,"json" )==0 )
		strcpy(contentType,"application/json");
	else if(strcmp(t,"gif")==0)
		strcpy(contentType,"image/gif");
	else if(strcmp(t,"html")==0 || strcmp(t,"htm")==0)
		strcpy(contentType,"text/html");
	else if(strcmp(t,"php")==0)
		strcpy(contentType,"text/html");
	else if(strcmp(t,"js")==0)
		strcpy(contentType,"application/x-javascript");
	else if(strcmp(t,"css")==0)
		strcpy(contentType,"text/css");
	else 
		strcpy(contentType,"text/html");
	return contentType;
}

char * getGMTime(){
	static char szBuf[128]={0}; 
	time_t tnow = time(NULL);        
	strftime(szBuf,127,"%a,%d %b %Y %H:%M:%S",gmtime(&tnow)); 
	return szBuf;
}

int read_oneline(char *buf, char* line){
	int size = strlen( buf );
	int i = 0;
	for(i = 0;i <size; ++i){
		char ch = buf[i];
		if(ch == '\n') 
			break;
		else
			line[i] = ch;
	}
	return i+1;
}

int web_request(websvr_t* p, int sock, char* data, size_t len){
	char METHORD[256];
	char TARGET[256];
	char REQUEST[256];
	/*
	POST / HTTP1.1
	Host:www.wrox.com
	User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)
	Content-Type:application/x-www-form-urlencoded
	Content-Length:40
	Connection: Keep-Alive

	name=Professional%20Ajax&publisher=Wiley
	*/
	char line[256] = {0};
	memset( line, 0x00, sizeof(line) );
	read_oneline( data, line );
	char szargs[256] = { 0 };
	sscanf(line, "%[^ ] %[^( |?)]?%[^ ]*", METHORD, TARGET, szargs);

	//http head context
	while(1){
		//read_line( data[i], line );
		break;
	}

	static char send_buf[MAX_BUF_SIZE];
	memset(send_buf, 0x00, sizeof(send_buf));
	int bufLen = sprintf(send_buf, "HTTP/1.1 200 OK \r\n \
								   Date: %s GMT\r\n \
								   Expires: %s GMT\r\n \
								   Cache-Control: private, max-age=31536000\r\n \
								   X-Content-Type-Options: nosniff\r\n \
								   Server: smartx\r\n \
								   Content-Type: %s\r\n",
								   getGMTime(),
								   getGMTime(),
								   getContent("xx"));

	if ( strcmp(METHORD,"LUAGET")==0){
		static char response[MAX_BUF_SIZE] = {0};
		int len = p->dispath(TARGET, REQUEST, response );
		bufLen += sprintf(send_buf + bufLen,"Content-Length: %d\r\n\r\n",len);
		send_pkg(sock, send_buf, bufLen);
		send_pkg(sock, &response[0], len);
		return 0;
	}
	else if ( strcmp(METHORD,"LUAPOST")==0){



		//this->dispath();
		return 0;
	}

 
	static char webpath[256] = {0};
	sprintf(webpath,"./%s", TARGET);

	/*

	FILE* f=fopen(webpath,"rb");
	if( f == NULL ){
		static char defPage[]="<html><b><center>404 not find!</center></b></html>";
		bufLen += sprintf(send_buf+bufLen,"Content-Length: %ld\r\n\r\n%s",strlen(defPage),defPage);
		send_pkg(sock,send_buf,bufLen);
		return 0;
	}
	fseek(f,0,SEEK_END);
	int pos = ftell(f);
	bufLen += sprintf(send_buf+bufLen,"Content-Length: %d\r\n\r\n",pos);
	send_pkg(sock, send_buf, bufLen);
	fseek(f,0,SEEK_SET);
	int nbs = MAX_BUF_SIZE;
	int npieces = (pos + nbs-1)/nbs;
	for( int i=0; i<npieces; i++ ){
		int fl = fread(send_buf,1,nbs,f);
		send_pkg(sock,send_buf,fl); 
	}
	fclose(f);
	*/
	return 0;
}
 
 
 void workthread( void* ptr ){
	websvr_t * p = (websvr_t*)ptr;
	while( !p->bExit ){
		fd_set fdRead;
		FD_ZERO(&fdRead);
		FD_SET( p->mysock_fd, &fdRead );  
		for( int nLoopi = 0; nLoopi < MAX_CLIENT; nLoopi++ ){
			if( fdarray[nLoopi] !=0 )
				FD_SET( fdarray[nLoopi], &fdRead );
		}
		//
		struct timeval tv={0,100000};
		int maxfd = p->mysock_fd;  
		if( select( maxfd + 1, &fdRead, NULL, NULL, &tv ) <= 0 )
			continue;
	    //ACCEPT CONNECT
		if( FD_ISSET( p->mysock_fd, &fdRead ) ){
			struct sockaddr_in clientaddr;
			bzero(&clientaddr, sizeof(clientaddr));
			socklen_t clilen = sizeof(struct sockaddr_in );
			int aptclt = accept(p->mysock_fd, (struct sockaddr *)&clientaddr, &clilen);
			int bAccept = 0;
			for(int nLoopi=0; aptclt>0 && nLoopi<MAX_CLIENT; nLoopi++ ){
				if( fdarray[nLoopi] == 0 ){
					fdarray[nLoopi] = aptclt;
					fcntl(aptclt, F_SETFL, O_NONBLOCK);
					FD_SET(fdarray[nLoopi] , &fdRead);  
					if (maxfd<aptclt)maxfd = aptclt; 
					bAccept = 1;
					break;
				}
			}
			if( !bAccept ){
				close( aptclt );
			}
			continue;
		}
		//RECV
		for( int nLoopi = 0; nLoopi < MAX_CLIENT; nLoopi++ ){
			if( FD_ISSET(fdarray[nLoopi], &fdRead) ){
				static char data[MAX_BUF_SIZE] = {0};
				memset(data, 0x00, MAX_BUF_SIZE);
				int cnt = -1;
				int tln = 0;
				do {
					cnt = recv(fdarray[nLoopi], &data[tln], MAX_BUF_SIZE -tln, 0);
					tln += cnt;
				} while (cnt > 0);
				int bshutdown = 1;
				if( tln > 0 ){
					bshutdown = web_request(p,fdarray[nLoopi],data,tln);
				}
				if (bshutdown || tln<=0) {
					close(fdarray[nLoopi]);
					FD_CLR( fdarray[nLoopi], &fdRead );
					fdarray[nLoopi] = 0;
				}
			}
		}
	}
	return;
}