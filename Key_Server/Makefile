LFLAGS += -lcrypto -lssl

all: Key_server

Key_server.o: Key_server.c
	cc -g -c -Wall -Werror Key_server.c $(LFLAGS) 

Key_server: Key_server.o ../security_ssl.o ../utils.o
	cc -g -o key_server Key_server.o ../security_ssl.o ../utils.o $(LFLAGS) 

