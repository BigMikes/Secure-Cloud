#include "../security_ssl.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>


struct server_ctx{
	int server_sk;
	int to_client_sk;
	SSL_CTX* ssl_factory;
	SSL* connection;
	char* certif_path;
	char* prvkey_path;
	char* address;
	int port;
};


void help(){
	char* options_msg = "Usage: Files_server <ip address> <port number>\n\
	[Optionals:] <certificate path> <private key path>\n";
        
	printf("%s", options_msg);		
}

//restituisce il descrittore del socket server
int create_socket(char* address, int port){
	int ret;
	int lst_sk;		//socket del server
	//struttura dati per l'indirizzo e porta del server
	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET; // IPv4
	my_addr.sin_port = htons((uint16_t) port);
	inet_pton(AF_INET, address, &my_addr.sin_addr);
	//Socket
	lst_sk = socket(AF_INET, SOCK_STREAM, 0);
	if(lst_sk == -1){
		printf("I can't open the socket!");
      		exit(-1);
	}
	//setto il riuso dell'indirizzo
	int optval = 1;
	setsockopt(lst_sk, SOL_SOCKET,SO_REUSEADDR, &optval, sizeof(optval));
	//lego l'indirizzo al socket
	ret = bind(lst_sk, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret == -1){
		printf("Error in socket bind");
		exit(-1);	
	}
	return lst_sk;
}


//si pone in ascolto di connessioni dal client, le accetta e restituisce il socket creato per lo scambio dati
int accept_client(int server_sk){
	int client_addr_len;
	int com_sk;
	int ret;
	struct sockaddr client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	//mi pongo in ascolto sulla porta
	ret = listen(server_sk, SOMAXCONN);
	if(ret == -1){
		printf("Error in listen");
		exit(-1);	
	}
	//attendo nuove connessioni da parte dei client
	//client_addr_len = sizeof(client_addr);
	com_sk = accept(server_sk, (struct sockaddr*)&client_addr, &client_addr_len);
	if(com_sk == -1){
		printf("Error in accept");
		exit(-1);	
	}
	return com_sk;
}

//funzione che libera tutte le strutture dati del server
void server_cleanup(struct server_ctx* server){
	if(server->certif_path != NULL)
		free(server->certif_path);
	if(server->prvkey_path != NULL)
		free(server->prvkey_path);
	if(server->address != NULL)
		free(server->address);
	if(server->connection != NULL){
		SSL_shutdown(server->connection);
		SSL_free(server->connection);
	}
	if(server->to_client_sk != 0)
		close(server->to_client_sk);
	if(server->server_sk != 0)
		close(server->server_sk);
	if(server->ssl_factory != NULL)
		SSL_CTX_free(server->ssl_factory);
}


int main(int argc, char* argv[]){
	int ret;
	struct server_ctx server;
	memset(&server, 0, sizeof(struct server_ctx));
	//controllo che i parametri obbligatori (address e port) ci siano
	if(argc < 3){
		help();
		exit(-1);
	}
	//leggo address e port dai parametri d'ingresso
	server.address = strdup(argv[1]);
	server.port = atoi(argv[2]);
	
	//leggo certificate path e prvkey path, se non presenti li setto a valori di default
	if(argc == 5){
		server.certif_path = strdup(argv[3]);
		server.prvkey_path = strdup(argv[4]);
	}
	else{
		server.certif_path = "./Certs/fileserver_cert.pem";
		server.prvkey_path = "./Certs/fileserver_prvkey.pem";
	}
		
	//create the ssl context
	server.ssl_factory = create_SSL_context_server(server.certif_path, server.prvkey_path);	
	if(server.ssl_factory == NULL)
		exit(-1);
				
	//create the socket
	server.server_sk = create_socket(server.address, server.port);
	//connect with the client
	server.to_client_sk = accept_client(server.server_sk);
	
	//bind the classic socket to ssl socket
	server.connection = bind_socket_to_SSL(server.ssl_factory, server.to_client_sk);
	if(server.connection == NULL){
		server_cleanup(&server);
		exit(-1);
	}
	//accept new ssl connection	
	ret = server_accept(server.connection);
	if(ret != 1){
		server_cleanup(&server);
		exit(-1);
	}
	
	
	server_cleanup(&server);
	exit(0);
}
