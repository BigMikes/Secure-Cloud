LFLAGS += -lcrypto -lssl

all: client

client.o: client.c
	cc -g -c -Wall -Werror client.c -lssl -lcrypto

client: client.o ../security_ssl.o ../utils.o
	cc -g -o client client.o ../security_ssl.o ../utils.o $(LFLAGS) 

