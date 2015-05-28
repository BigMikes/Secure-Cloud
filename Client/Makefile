compile: client

utils.o: ../utils.h ../utils.c
	cc -g -c ../utils.c -lcrypto
	
security_ssl.o: ../security_ssl.c ../security_ssl.h
	cc -g -c ../security_ssl.c -lssl -lcrypto

client.o: client.c
	cc -g -c -Wall -Werror client.c -lssl -lcrypto

client: client.o ../security_ssl.o ../utils.o
	cc -g -o client client.o ../security_ssl.o ../utils.o -lssl -lcrypto

clear:
	rm *.o
	rm client
