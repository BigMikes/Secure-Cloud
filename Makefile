LFLAGS += -lcrypto -lssl

all: files_server client key_server

utils.o: utils.h utils.c
	cc -g -c  utils.c $(LFLAGS)
	
security_ssl.o: security_ssl.c security_ssl.h
	cc -g -c  security_ssl.c $(LFLAGS) 

files_server: utils.o security_ssl.o
	make -C Files_Server all
	
key_server: utils.o security_ssl.o
	make -C Key_Server all
	
client: utils.o security_ssl.o
	make -C Client all
	
clear:
	rm *.o
	rm */*.o
	rm Client/client
	rm Files_Server/files_server
	rm Key_Server/key_server
