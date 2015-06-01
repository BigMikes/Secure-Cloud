compile: Key_server

utils.o: ../utils.h ../utils.c
	cc -g -c ../utils.c -lcrypto
	
security_ssl.o: ../security_ssl.c ../security_ssl.h
	cc -g -c ../security_ssl.c -lssl -lcrypto

Key_server.o: Key_server.c
	cc -g -c -Wall -Werror Key_server.c -lcrypto

Key_server: Key_server.o ../security_ssl.o ../utils.o
	cc -g -o key_server Key_server.o ../security_ssl.o ../utils.o -lssl -lcrypto

clean:
	rm *.o
	rm key_server
