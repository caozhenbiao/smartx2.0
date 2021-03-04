#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <netinet/in.h>

#define endian_swap16(x) (x)

typedef struct _ip_hdr{
    #if LITTLE_ENDIAN
    unsigned char ihl:4;   //首部长度
    unsigned char version:4; //版本
    #else
    unsigned char version:4; //版本
    unsigned char ihl:4;   //首部长度
    #endif
    unsigned char tos;   //服务类型
    unsigned short tot_len; //总长度
    unsigned short id;    //标志
    unsigned short frag_off; //分片偏移
    unsigned char ttl;   //生存时间
    unsigned char protocol; //协议
    unsigned short chk_sum; //检验和
    struct in_addr srcaddr; //源IP地址
    struct in_addr dstaddr; //目的IP地址
}ip_hdr;

int interface_start(const char* file);
int install(lua_State* L);
int transmit(lua_State* L);
int option(lua_State* L);
int lua_execute(char* func, char* sjson);

uint8_t  checksum( unsigned char * buf, size_t len);
uint8_t  is_ippackage( uint8_t* buf, uint16_t len );
uint16_t lanip_response(uint32_t lanip,uint8_t* data);
uint16_t tun_datapkg( uint8_t* buf, uint16_t len, uint8_t* data);
uint16_t lua_datapkg( char* request, uint8_t* data);

int verify_user(int fd, unsigned int* lip, const char* data, size_t len );
int verity_request(const char* name, const char* pwd, char* data);


#ifdef __cplusplus
}
#endif

#endif

