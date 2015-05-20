#include "../security_ssl.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

int create_socket(char* address, int port){
	int ret;
	int lst_sk;		//socket del server
	//struttura dati per l'indirizzo e porta del server
	struct sockaddr_in server_addr;
	
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET; // IPv4
	server_addr.sin_port = htons((uint16_t) port);
	inet_pton(AF_INET, address, &server_addr.sin_addr);
	//Socket
	lst_sk = socket(AF_INET, SOCK_STREAM, 0);
	if(lst_sk == -1){
		printf("I can't open the socket!");
      		exit(-1);
	}
	//mi connetto al server
	ret = connect(lst_sk, (struct sockaddr*) &server_addr, sizeof(server_addr));
	if(ret == -1){
		printf("Error in connect operation\n");
	}
	return lst_sk;
}

//accetta in ingresso indirizzo ip e porta
int main(int argc,char* argv[]){
	int ret;
	int socketS;
	char* addr;
	int port;
	char* certif_path;
	SSL_CTX* ssl_factory;
	SSL* connection;
	
	/////////////////////////////////////////////////////////////////error check
	if(argc < 3) {
		printf("Errore nel passaggio dei parametri\n");
		return -1;
	}
	
	
	////////////////////////////////////////////////////////////inizializzazioni
	addr = argv[1];
	port = atoi(argv[2]);
	
	if(argc == 4){
		certif_path = strdup(argv[3]);
	}
	else{
		certif_path = "./Certs/ca_cert.pem";
	}
	
	
	////////////////////////////////////////////////////////////////////////body
	ssl_factory = create_SSL_context_client(certif_path);	
	if(ssl_factory == NULL)
		exit(-1);
	
	socketS = create_socket(addr, port);
	printf("Connessione al server %s (porta %i) effettuata con successo\n", addr, port);
	
	connection = bind_socket_to_SSL(ssl_factory, socketS);
	if(connection == NULL){
		exit(-1);
	}
	
	/*
	iniziare la connessione con la secure_write
	*/
	
	ret = client_connect(connection);
	if(ret != 1){
		exit(-1);
	}
	printf("Connection succefully\n");
	
	secure_write(0, "Ciao\0", 5, connection); 
	/////////////////////////////////////////////////////////////////////cleanup
	if(-1 == close(socketS)){
		printf("Error in closing operation.\n");
	}
	
	ssl_context_cleanup(ssl_factory);
	return 0;
}
