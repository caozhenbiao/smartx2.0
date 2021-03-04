CC = gcc
XX = g++
TARGET = ./smartx.exe
CFLAGS = -Wall -O -g -I./lib -I../libs/lua/src
LIBS =  -lpthread -lcstl -llua -ldl

%.o: %.c                                 
	$(CC) $(CFLAGS) -c $< -o $@

%.o:%.cpp
	$(XX) $(CFLAGS) -c $< -o $@

SOURCES = $(wildcard ./src/inc/cJSON.c ./src/osapi.c ./src/interface.c ./src/firewall.c ./src/vpnsvr.c ./src/websvr.c  ./src/main.c)
OBJS = $(patsubst %.c,%.o,$(patsubst %.c,%.o,$(SOURCES)))  

$(TARGET) : $(OBJS)
	$(XX) $(OBJS) -o $(TARGET) $(LIBS)
	chmod a+x $(TARGET)

clean:
	rm -rf $(OBJS) $(TARGET)

