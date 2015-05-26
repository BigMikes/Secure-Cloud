compile: client

utils.o: ../utils.h ../utils.c
	cc -g -c  ../utils.c -lcrypto
	
security_ssl.o: ../security_ssl.c ../security_ssl.h
	cc -g -c  ../security_ssl.c -lssl -lcrypto

client.o: client.c
	cc -g -c  client.c
	
files_server: ../utils.o client.o ../security_ssl.o
	cc -g -o client ../utils.o client.o ../security_ssl.o -lcrypto -lssl

