#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "interface.h"
#include "websvr.h"
#include "vpnsvr.h"

volatile sig_atomic_t exit_signal_received;
static void signal_handler(int sig){
    signal(sig, SIG_DFL);
    exit_signal_received = 1;
}

int vpndispath(char* func, char* data, char* response){

    return 0;
}

int webdispath(char* func, char* data, char* response){
    lua_execute(func,data);
    return 0;
}

void usage(){
    printf("please spc type!\n");
}

int main(int argc, char *argv[]){
	printf("smartvpn start.\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    int is_vpnsvr = -1;
    char vpn_address[40]={0};
    char web_address[40]={0};
    uint16_t vpn_port = 1959;
    uint16_t web_port = 80;
    if( argc>1 && strcmp(argv[1],"server")==0 ){
        strcpy(vpn_address,"0.0.0.0");
        is_vpnsvr = 1;
    }
    else if( argc>1 && strcmp(argv[1],"client")==0 ){
        strcpy(vpn_address,"165.232.165.209");
        is_vpnsvr = 0;
    }
    else{
        usage();
        return 0;
    }
	int c = 0;
	while((c=getopt(argc, argv, "t:a:p:"))!=-1){
		switch (c){
			case 't': is_vpnsvr = strcmp(optarg,"client"); break;
            case 'a': strncpy(vpn_address,optarg,40); break;
			case 'p': vpn_port = atoi(optarg); break;
            case 'w': strncpy(web_address,optarg,40); break;
			default :break;
		}
	}
    vpnsvr_t * vpnsvr = create_vpnsvr(vpndispath,is_vpnsvr,vpn_address,vpn_port);
    websvr_t * websvr = create_websvr(webdispath,web_address,web_port);
    interface_start("./main.lua");
    lua_execute("luaTest","lua test function");
	while( exit_signal_received == 0 ) {
        printf("%s cmd>",argv[1]);
		char sz[256] ={0};
		if( fgets(sz,256,stdin) == NULL )
			continue;
		if (strcmp(sz, "exit\n") == 0)
			break;
	}
    lua_execute("luaTest","lua test function");
    destroy_websvr(&websvr);
    destroy_vpnsvr(&vpnsvr);
    return 0;
}

