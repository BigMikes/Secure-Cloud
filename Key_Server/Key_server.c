#include "../security_ssl.h"
#include "../utils.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>

void CloseSocket(int sock)
{
  close(sock);
  return;
}

int create_socket(char* address, int port) {
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

void send_msg(int sock, void* Messaggio, int count) {
	printf("Client send: %s\n", (char*)Messaggio);
  
	if (write(sock, Messaggio, count) < 0){
		printf("Impossibile mandare il messaggio.\n");
		CloseSocket(sock);
		exit(1);
	}  
	printf("Messaggio spedito con successo.\n");
}

void recv_msg(int sock, void* Messaggio, int count) {
	if (read(sock, Messaggio, count) < 0)
	{
		printf("Impossibile ricevere il messaggio.\n");
		CloseSocket(sock);
		exit(1);
	}  
	printf("Messaggio ricevuto con successo: %s\n", (char*)Messaggio);
}


/*
 * 4 argomenti
 * 	indirizzo server
 * 	porta server 
 * 	[certificato File_server]
 */
int main(int argc, char* argv[]) {
	//variabili
	char* addr;
	int port;
	char* File_server_pub_key;
	int socketF;
	
	//controlli
	if(argc < 3) {
		printf("Errore nel passaggio dei parametri\n");
		return -1;
	}
	
	//inizializzazioni
	addr = argv[1];
	port = atoi(argv[2]);
	
	if(argc == 4){
		File_server_pub_key = strdup(argv[3]);
	}
	else{
		File_server_pub_key = "./Certs/fileserver_pubkey.pem";
	}
	
	
	//set up
	socketF = create_socket(addr, port);
	printf("Connessione al server %s (porta %i) effettuata con successo\n", addr, port);
	
	char* test = "ciao";
	send_msg(socketF, test, strlen(test));
	File_server_pub_key++;
	//hand shake iniziale
	//send{ File_server, Key_server, noncep }Kf+
	
	//receive( {File_server, Key_server, noncep, nonces, K}kk+ )
	
	//send( {nonces}K )
	
	while( 1 ){
		//ciclo di richieste del server
		//la richiesta può essere di storage o di retrieve
	}
	
	return 0;
}
