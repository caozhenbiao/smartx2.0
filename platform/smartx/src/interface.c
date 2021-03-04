#include <stdint.h>
#include "interface.h"
#include "./inc/cJSON.h"

static int luatrans = LUA_REFNIL;
static int luatimer = LUA_REFNIL;
static int luaclose = LUA_REFNIL;
lua_State * theState = NULL;
static uint16_t frame_sec = 0;

int install(lua_State* L){
	theState = L;
	unsigned int tmval  = (unsigned int)lua_tointeger(L,1);
	luaclose = luaL_ref(L,LUA_REGISTRYINDEX);
	luatimer = luaL_ref(L,LUA_REGISTRYINDEX);
	luatrans = luaL_ref(L,LUA_REGISTRYINDEX);
	printf("lua install :%d\n",tmval);
	//business->startwork();
	return 0;
}

int transmit(lua_State* L){
	size_t      size   = (size_t)luaL_checkinteger(L,1);
	const char* buf    = luaL_checklstring(L,2, &size);
	//business->tranmit(buf,size);
	printf("%s\n",buf );
	lua_pushnumber(L, 0 );
	return 1;
}

int option(lua_State* L){
	//lua_pushstring(L, business->myoption);
	return 1;
}

int interface_start(const char* file){
	printf("lua interface service start:%s.\n", file);
	theState = luaL_newstate();
	luaL_openlibs( theState );
	if(luaL_loadfile(theState, file)){
		printf("script error or file:%s mission!\n", file);
		lua_close(theState);
		theState = NULL;
		return 0;
	}
	lua_register( theState, "install",install);
	lua_register( theState, "transmit", transmit );
	lua_register( theState, "option", option );
	lua_pcall(theState, 0, LUA_MULTRET, 0);
	return 0;
}

int interface_stop(){
	if(!theState)	
		return 0;
	lua_rawgeti( theState, LUA_REGISTRYINDEX, luaclose);
	lua_pcall(theState,0,0,0);
	lua_close(theState);
	theState = NULL;
	return 0;
}

int lua_execute(char* func, char* sjson){
	static unsigned int tms = 0;
	tms++;
//	if (theState && 0 != luaL_lock(theState)) {
//		return 0;
//	}
	lua_getglobal(theState, func);
	lua_pushstring(theState, sjson);
	lua_pcall(theState, 1, 1, 0);
	char* ret = (char*)lua_tostring(theState, -1);
	printf("lua dispath tms:%d,%s(%s) ret:%s\n",tms, func, sjson, ret);
//	luaL_unlock(theState);
	return 0;
}

uint8_t checksum(unsigned char * buf, size_t len){
    uint8_t cs = 0;
    for( size_t i=0; i<len; i++ )
        cs += buf[i];
    return cs;
}

uint8_t is_ippackage( uint8_t* buf, uint16_t len ){
    ip_hdr hdr;
    memcpy( &hdr, buf, sizeof(ip_hdr));
    return 0;
}

uint16_t lanip_response(uint32_t lanip, uint8_t* data){
    unsigned char cs = checksum((unsigned char*)(&lanip),4);
    unsigned short len = 4;
    memset(data, 0x00, 65535);
    memcpy(data, &len, 2);
    memcpy(data+8, &lanip, 4);
    memcpy(data+8+len, &cs, 1);
    return len+9;
}

uint16_t tun_datapkg(uint8_t* buf, uint16_t len, uint8_t* data){
    unsigned char cs = checksum(buf,len);
    memset(data, 0x00, 65535);
    memcpy(data, &len, 2);
    memcpy(data+2, &frame_sec, 2);
    memcpy(data+8, buf, len);
    memcpy(data+8+len, &cs, 1);
    frame_sec++;
    return len+9;
}

uint16_t lua_datapkg(char* request, uint8_t* data){
    unsigned short len = strlen( request );
    unsigned char cs = checksum((unsigned char*)request,len );
    memset(data, 0x00, 65535);
    memcpy(data, &len, 2);
    memcpy(data+2, &frame_sec, 2);
    memcpy(data+8, request, len);
    memcpy(data+8+len, &cs, 1);
    frame_sec++;
    return len+9;
}

int verity_request(const char* name, const char* pwd, char* data){
    static char buf[256] = {0};
    int len = sprintf(buf, "{\"user\":\"%s\",\"pwd\":\"%s\"}", name, pwd);
    unsigned char cs = checksum((uint8_t*)buf,len);
    memset( data, 0x00, 256 );
    memcpy( data, &len, 2);
    memcpy( data+2, &frame_sec, 2);
    memcpy( data+8, buf, len);
    memcpy( data+8+len, &cs, 1);
    return len+9;
}

int verify_user(int fd, unsigned int * lip, const char* data, size_t len){
    char newdata[256] = {0};
    uint16_t binlen = 0;
    memcpy(&binlen, data, 2);
    uint16_t dlen = endian_swap16(binlen);
    memcpy( newdata, data+8, dlen );
    static unsigned int g_curip = 0x1C0A8C0; //192.168.192.2
	printf("data:%s\n",newdata);
    //int nsent = send( interfacefd, data, len , 0 );
    //int nrecv = recv( interfacefd, data, 65505, 0 );
    char *out;cJSON *json;
    json=cJSON_Parse(newdata);
    if (!json) {
        printf("Error before: [%s]\n",cJSON_GetErrorPtr());
        return -1;
    }
    g_curip += (1<<24);
    *lip = g_curip;
    printf("ip:%d    %d\n", g_curip, *lip);
    out=cJSON_Print(json);
    cJSON_Delete(json);
    printf("%s\n",out);
    free(out);
    return 0;
}
 
 int respons_verfy( int fd ){
    //unsigned char buf[64]={0};
    //int nsent = write( fd, buf, 64 , 0 );
    return 0;
 }