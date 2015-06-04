LFLAGS += -lcrypto -lssl

all: files_server

Shamir_sharing.o: Shamir_sharing.c Shamir_sharing.h
	cc -g -c  Shamir_sharing.c

Files_Server.o: Files_Server.c
	cc -g -c  Files_Server.c
	
files_server: ../utils.o Files_Server.o ../security_ssl.o Shamir_sharing.o
	cc -g -o files_server ../utils.o Files_Server.o ../security_ssl.o Shamir_sharing.o $(LFLAGS) 

