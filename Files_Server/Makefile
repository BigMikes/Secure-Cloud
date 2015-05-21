compile: files_server

utils.o: ../utils.h ../utils.c
	cc -g -c  ../utils.c -lcrypto
	
security_ssl.o: ../security_ssl.c ../security_ssl.h
	cc -g -c  ../security_ssl.c -lssl -lcrypto

Files_Server.o: Files_Server.c
	cc -g -c  Files_Server.c
	
files_server: ../utils.o Files_Server.o ../security_ssl.o
	cc -g -o files_server ../utils.o Files_Server.o ../security_ssl.o -lcrypto -lssl

