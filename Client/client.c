#include "../security_ssl.h"
#include "../utils.h"
#include "upload.c"
#include "download.c"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

//costanti
#define DIM_BUFFER 1024
#define DIM_USER_FIELD 50

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

void check_ret(int a, int b){
	if(a != b)
		exit (EXIT_FAILURE);
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

	
	//user data
	char username[DIM_USER_FIELD];
	int dim_username;
	char password[DIM_USER_FIELD];
	int dim_password;
	char support;
	uint8_t command;
	char file_name[DIM_USER_FIELD];
	int dim_file_name;
	
	//server response
	uint8_t server_response;
	

	
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
	
	ret = client_connect(connection);
	if(ret != 1){
		exit(-1);
	}
	printf("Connection succefully\n");
	
	//secure_write(0, "Ciao\0", 5, connection); 
	////////////////////////////////////////////////////////////////////////body
	printf("Username:\n");
	dim_username = scanf("%s", username);
	if( dim_username == 0){
		printf("Error");
		exit(-1);
	}
	
	printf("\nPassword:\n");
	dim_password = scanf("%s", password);
	if( dim_password == 0){
		printf("Error");
		exit(-1);
	}
	
	printf("\n Operation Upload or Download (u/d):\n");
	scanf("%c", &support);
	switch(support){
		case 'u':
		case 'U':
			command = 1;
			break;
		case 'd':
		case 'D':
			command = 2;
			break;
		default:
			printf("Error");
			exit(-1);
	}
	
	//primo messaggio user || pwd || cmd || name_file
	ret = secure_write(0, dim_username, 4, connection); 
	check_ret(ret, 4);
	ret = secure_write(0, username, dim_username, connection);
	check_ret(ret, dim_username);
	ret = secure_write(0, dim_password, 4, connection); 
	check_ret(ret, 4);
	ret = secure_write(0, password, dim_password, connection); 
	check_ret(ret, dim_password);
	ret = secure_write(0, command, 1, connection); 
	check_ret(ret, 1);
	ret = secure_write(0, dim_file_name, 4, connection); 
	check_ret(ret, 4);
	ret = secure_write(0, file_name, dim_file_name, connection); 
	check_ret(ret, dim_file_name);
	
	//wait for response
	ret = secure_read(0, &server_response, sizeof(uint8_t), connection);
	check_ret(ret, sizeof(uint8_t));
	if(server_response == 0){
		printf("Connection refused.\n");
		exit(-1);
	}
	
	if(command == 1){
		upload(connection, file_name, dim_file_name);
	}else{
		//download();
	}
	
	
	/////////////////////////////////////////////////////////////////////cleanup
	if(-1 == close(socketS)){
		printf("Error in closing operation.\n");
	}
	
	ssl_context_cleanup(ssl_factory);
	return 0;
}
