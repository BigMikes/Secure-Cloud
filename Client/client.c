#include "../security_ssl.h"
#include "../utils.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>


//costanti
#define DIM_BUFFER 1024
#define DIM_USER_FIELD 50
#define CMD_UPLOAD 1
#define CMD_DOWNLOAD 2
#define UPDATE_FAIL 	0
#define UPDATE_OK 	1

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
		exit(EXIT_FAILURE);
}


int close_ssl(SSL* connection, int socket){
	int ret = 0;
	ret += SSL_shutdown(connection);
	ret += close(socket);
	SSL_free(connection);
	
	return (ret < 0) ? -1 : 0;
}

//accetta in ingresso indirizzo ip, porta e certificato opzionale
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
	

	
	////error check
	if(argc < 3) {
		printf("Errore nel passaggio dei parametri\n");
		return -1;
	}
	
	
	////inizializzazioni
	addr = argv[1];
	port = atoi(argv[2]);
	
	if(argc == 4){
		certif_path = strdup(argv[3]);
	}
	else{
		certif_path = "./Certs/ca_cert.pem";
	}
	
	
	////start ssl
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
	printf("Connection succefull\n");
	
	////body
	printf("Username:\n");
	ret = scanf("%s", username);
	dim_username = strlen(username);
	//printf("user: %s len: %i \n", username, dim_username);
	
	printf("\nPassword:\n");
	ret = scanf("%s", password);
	dim_password = strlen(password);
	//printf("password: %s len: %i\n", password, dim_password);
	
	printf("\nOperation Upload or Download (u/d):\n");
	support = (char)getchar();
	support = (char)getchar();
	//printf("Command: %c\n", support);
	switch(support){
		case 'u':
		case 'U':
			command = CMD_UPLOAD;
			break;
		case 'd':
		case 'D':
			command = CMD_DOWNLOAD;
			break;
		default:
			printf("Error\n");
			if(-1 == close_ssl(connection, socketS)){
				printf("Error in closing operation.\n");
			}
			exit(-1);
	}
	
	printf("\nFile name:\n");
	ret = scanf("%s", file_name);
	
	//In case of Upload command: check if file exist and if is possible to read it
	if(command == CMD_UPLOAD){
		if( access( file_name, F_OK|R_OK ) != -1 ) {
			// file exists
		} else {
			// file doesn't exist
			printf("file doesn't exist or it's impossible to read.\n");
			if(-1 == close_ssl(connection, socketS)){
				printf("Error in closing operation.\n");
			}
			exit(-1);
		}
	}
	dim_file_name = strlen(file_name);
	//printf("File: %s len: %i\n", file_name, dim_file_name);
	
	//primo messaggio user || pwd || cmd || name_file
	//user_len
	ret = secure_write(0, &dim_username, sizeof(int), connection); 
	check_ret(ret, sizeof(int));
	//user
	ret = secure_write(0, username, dim_username, connection);
	check_ret(ret, dim_username);
	//pwd_len
	ret = secure_write(0, &dim_password, sizeof(int), connection); 
	check_ret(ret, sizeof(int));
	//pwd
	ret = secure_write(0, password, dim_password, connection); 
	check_ret(ret, dim_password);
	//cmd
	ret = secure_write(0, &command, sizeof(uint8_t), connection); 
	check_ret(ret, sizeof(uint8_t));
	//file_name_len
	ret = secure_write(0, &dim_file_name, sizeof(int), connection); 
	check_ret(ret, sizeof(int));
	//file_name
	ret = secure_write(0, file_name, dim_file_name, connection); 
	check_ret(ret, dim_file_name);
	
	//wait for response
	ret = secure_read(0, &server_response, sizeof(uint8_t), connection);
	check_ret(ret, sizeof(uint8_t));
	if(server_response == 0){
		printf("Connection refused.\n");
		exit(-1);
	}
	
	if(command == CMD_UPLOAD){
		//UPLOAD
		printf("UPLOAD\n");
		
		//symmetric cipher
		unsigned char* key;
		int key_len;
		
		//generate k
		key_len = EVP_CIPHER_key_length(SYM_CIPHER);
		key = (unsigned char*)malloc(key_len);
		RAND_seed(key, key_len);
		RAND_bytes(key, key_len);
		
		//encrypt file
		unsigned char* hash = do_hash(NULL, 0, file_name);
		int cipher_file_len;
		unsigned char* cipher_file = sym_crypto_file(file_name, hash, EVP_MD_size(HASH_FUN), key, &cipher_file_len);
		
		//send file size
		ret = secure_write(0, &cipher_file_len, sizeof(int), connection); 
		check_ret(ret, sizeof(int));
		//send file
		ret = secure_write(0, cipher_file, cipher_file_len, connection); 
		check_ret(ret, cipher_file_len);
		
		//send k
		ret = secure_write(0, key, key_len, connection); 
		check_ret(ret, key_len);
		
		
		//wait for response
		ret = secure_read(0, &server_response, sizeof(uint8_t), connection);
		check_ret(ret, sizeof(uint8_t));

		if(server_response == UPDATE_OK)
			printf("Upload successfully\n");
		else
			printf("Upload error\n");	
		//clear 
		memset(cipher_file, 0, cipher_file_len);
		free(cipher_file);
		memset(key, 0, key_len);
		free(key);
	} else {
		printf("DOWNLOAD\n");
		
		//variabili
		unsigned char* key;
		int key_len;
		
		//read key
		key_len = EVP_CIPHER_key_length(SYM_CIPHER);
		key = (unsigned char*)malloc(key_len);
		ret = secure_read(0, key, key_len, connection);
		//printf("Ret = %i, key_len = %i\n", ret, key_len);
		check_ret(ret, key_len);
		
		//read Ek(file || H(file))
		int cipher_len;
		unsigned char* cipher_buff;
		
		//read file size
		ret = secure_read(0, &cipher_len, sizeof(int), connection);
		check_ret(ret, sizeof(int));
		//printf("Ret = %i, cipher_len = %i\n", ret, cipher_len);
		
		//read file
		cipher_buff = malloc(cipher_len);
		if(cipher_buff == NULL)
			exit(-1);
		ret = 0;
		while(ret < cipher_len){
			ret += secure_read(0, cipher_buff + ret, cipher_len - ret, connection);
			//printf("Ret = %i\n", ret);
			/*if(ret != cipher_len){
				memset(cipher_buff, 0, ret);
				free(cipher_buff);
				exit(-1);
			}*/
		}
		//printf("Ret = %i\n", ret);
		
		//decrypt
		int plain_len;
		char* plain = sym_decrypt(cipher_buff, cipher_len, key, &plain_len);
		
		//printf("plain: %.*s\n", plain_len, plain);
		
		//write to file
		FILE* output = fopen(file_name, "w");
		if(output == NULL){
			printf("Impossible to write file");
			exit(-1);
		}
		ret = fwrite(plain, sizeof(char), plain_len - 32, output);
		check_ret(ret, plain_len);
		fclose(output);
		
		printf("File \"%.*s\" created.\n", dim_file_name, file_name);
		
		//check hash
		if(verify_hash(NULL, 0, file_name, (unsigned char*)(plain + plain_len -32)) != 1){
			printf("corrupted\n");
			exit(-1);
		}
		printf("uncorrupted file \"%.*s\" ready.\n", dim_file_name, file_name);
		
		//clear
		free(cipher_buff);
		free(plain);
		memset(key, 0, key_len);
		free(key);
	}
	
	
	/////////////////////////////////////////////////////////////////////cleanup
	if(-1 == close_ssl(connection, socketS)){
		printf("Error in closing operation.\n");
	}
	
	ssl_context_cleanup(ssl_factory);
	return 0;
}
