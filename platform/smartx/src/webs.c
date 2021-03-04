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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "websvr.h"
#include <sstream>

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

websvr_t *create_websvr(void* disp, const uint8_t* ip, uint64_t port){
	if( self ){
		return self;
	}
    self = (websvr_t *)malloc(sizeof(websvr_t));  
    if (self != NULL){
        self->dispath = disp;
		self->mysvrport = port;
		self->bExit  = 0;
		strcpy( self->mysvrip, ip );
        printf("Create websvr successfully!\n");  
    }  

	struct sockaddr_in myaddr;
	myaddr.sin_family = AF_INET;
	//myaddr.sin_addr.s_addr = inet_addr( self->mysvrip );
	myaddr.sin_addr.s_addr = INADDR_ANY;
	myaddr.sin_port = htons( self->mysvrport );
	self->mysocket = socket( AF_INET, SOCK_STREAM, 0 );
	int ibind = bind( self->mysocket, (struct sockaddr_in*)&myaddr, sizeof(struct sockaddr_in));
	if( ibind != 0 ){
		printf("websvr bind socket error! addr=%s:%d\n",self->mysvrip,self->mysvrport);
		return ibind;
	}
	int ilisten = listen(self->mysocket, 50);  
	if( ilisten != 0  ){
		printf("websvr listen error!\n");
		return ilisten;
	}
	pthread_t theard1;
    char *message1 = "thread1";
    pthread_create(&theard1, NULL, (void *)&workthread, (void *)self);
    return self;  
}  

void destroy_websvr(websvr_t **p){
    if (*p != NULL){
		close((*p)->mysocket);
        free(*p);  
        *p = NULL;  
        printf("Delete websvr successfully!\n");  
    }  
} 

void workthread( void* ptr ){
	websvr_t * p = (websvr_t*)ptr;
	while( !p->bExit ){
		fd_set fdRead;
		FD_ZERO(&fdRead);
		FD_SET( p->mysocket, &fdRead );  
		for( int nLoopi = 0; nLoopi < MAX_CLIENT; nLoopi++ ){
			if( fdarray[nLoopi] !=0 )
				FD_SET( fdarray[nLoopi], &fdRead );
		}
		//
		struct timeval tv={0,100000};
		int maxfd = p->mysocket;  
		if( select( maxfd + 1, &fdRead, NULL, NULL, &tv ) <= 0 )
			continue;
	    //ACCEPT CONNECT
		if( FD_ISSET( p->mysocket, &fdRead ) ){
			struct sockaddr_in clientaddr;
			bzero(&clientaddr, sizeof(clientaddr));
			socklen_t clilen = sizeof(struct sockaddr_in );
			int aptclt = accept(p->mysocket, (struct sockaddr *)&clientaddr, &clilen);
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
					bshutdown = web_request(fdarray[nLoopi],data,tln);
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
 
char * getContent(const char* type){
	static char* contentType;
	if( strcmp(ftype,"png") == 0 )
		strcpy(contentType,"image/png");
	else if(strcmp(ftype,"jpeg")==0 || strcmp(ftype,"jpg")==0)
		strcpy(contentType,"image/jpeg");
	else if(strcmp(ftype,"json" )==0 )
		strcpy(contentType,"application/json");
	else if(strcmp(ftype,"gif")==0)
		strcpy(contentType,"image/gif");
	else if(strcmp(ftype,"html")==0 || strcmp(ftype,"htm")==0)
		strcpy(contentType,"text/html");
	else if(strcmp(ftype,"php")==0)
		strcpy(contentType,"text/html");
	else if(strcmp(ftype,"js")==0)
		strcpy(contentType,"application/x-javascript");
	else if(strcmp(ftype,"css")==0)
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

int16_t read_line(int fd,char *buf,int size){
	int i = 0;
	char ch;
	for(i = 0;i < size;++i){
		int n = recv(fd,&ch,1,0);
		if(1 == n){
			buf[i] = ch;
			if(ch == '\n') break;
		}else{
			return -1;
		}
	}
	return i+1;
}

int web_request(int sock, uint8_t* data, size_t len){
	char METHORD[256];
	char TARGET[256];
	char REQUEST[256];

	static char send_buf[MAX_BUF_SIZE];
	memset(send_buf, 0x00, sizeof(send_buf));
	int bufLen = sprintf(send_buf, "HTTP/1.1 200 OK \r\n \
								   Date: %s GMT\r\n \
								   Expires: %s GMT\r\n \
								   Cache-Control: private, max-age=31536000\r\n \
								   X-Content-Type-Options: nosniff\r\n \
								   Server: smartx\r\n \
								   Content-Type: %s\r\n",
								   getGMTime(),T
								   getGMTime(),
								   getContent());
	if ( strcmp(METHORD,"LUAGET")==0){
		static uint8_t response[MAX_BUF_SIZE] = 0;
		uint16_t len = self->dispath( REQUEST, response );
		bufLen += sprintf(send_buf + bufLen,"Content-Length: %ld\r\n\r\n",len);
		send_pkg(sock, send_buf, bufLen);
		send_pkg(sock, &response[0], len);
		return 0;
	}
	else if ( strcmp(METHORD,"LUAGET")==0){


		self->dispath( )
	
		return 0;
	}

	char TARGET[] = "file";
	static char webpath[256] = {0};
	sprintf(webpath,"./%s", TARGET)
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
	return 0;
}
 

 