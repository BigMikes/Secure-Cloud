/*
 * Password private key = "password"
*/

#include "../security_ssl.h"
#include "../utils.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>


/*---------CONSTANTS--------------*/
#define FILE_STORE "./File_store/"
#define BUF_DIM 512
#define HASH_DIM EVP_MD_size(EVP_sha256())
#define KEY_DIM EVP_CIPHER_key_length(EVP_aes_256_cbc())
#define MAX_USR_NAME 20
#define MAX_FILE_NAME 20

/*---------ERROR MESSAGES---------*/
#define AUTH_FAIL 0
#define AUTH_OK 1
#define NO_FILE 2
#define UPDATE_FAIL 0
#define UPDATE_OK 1

/*---------COMMAND MESSAGES-------*/
#define NO_AUTH -1
#define UPLOAD 1
#define DOWNLOAD 2


//Server context
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


struct client_ctx{
	char name[MAX_USR_NAME];
	char file_name[MAX_FILE_NAME];
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
	/*
	if(server->certif_path != NULL)
		free(server->certif_path);
	if(server->prvkey_path != NULL)
		free(server->prvkey_path);
	*/
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

/*
* Function that checks the password
*/
int find_usr_pwd(unsigned char* username, unsigned char* pwd, int dim_pwd){
    FILE *fp;
    int lines = 0;   // count how many lines are in the file
    int j = 0;
    int c;
    unsigned char* hash_pwd;
    char tmp_user[MAX_USR_NAME]; 		//Dimensione massima del nome utente 
    char tmp_pwd[HASH_DIM];
    int ret;
    
    fp = fopen("pwd.txt", "r");
    if(fp == NULL)
    	return -1;
    
    while(!feof(fp)) {
        c=fgetc(fp);
        if(c == '\n')
            lines++;
    }
    
    if(lines == 0){
    	fclose(fp);
    	return -1;
    }
    
    hash_pwd = do_hash(pwd, dim_pwd, NULL);
    
    rewind(fp);  // Line I added
        // read each line and put into accounts
    while(j != lines) {
        fscanf(fp, "%s ", tmp_user);
        fread(tmp_pwd, HASH_DIM, 1, fp);
        if(strcmp(tmp_user, username) == 0){
        	ret = CRYPTO_memcmp(hash_pwd, tmp_pwd, HASH_DIM);
        	free(hash_pwd);
        	fclose(fp);
        	return (ret == 0)? 1 : 0;
        }
       	j++;
    }
    free(hash_pwd);
    fclose(fp);
    return -1;
}

/*
* Function that adds a new user given his/her username and password
*/
int add_usr_pwd(unsigned char* username, unsigned char* pwd, int dim_pwd){
    FILE *fp;
    unsigned char* hash_pwd;
    int ret;
    
    fp = fopen("pwd.txt", "a");
    if(fp == NULL)
    	return -1;
    
    hash_pwd = do_hash(pwd, dim_pwd, NULL);
    
    fprintf(fp, "%s ", username);
    fwrite(hash_pwd, HASH_DIM, 1, fp); 
    fprintf(fp, "\n");
    free(hash_pwd);
    fclose(fp);
    return 1;
}

/*
* Reads the messages in format <size>||<content>
* The return buffer will contain the <content>
* The parameter value will contain the the <size> 
* Returns NULL in case of errors
*/
void* read_formatted(SSL* conn, int* size){
	int ret;
	void* buffer;
	int dim; 
	
	ret = secure_read(0, &dim, sizeof(int), conn);
	if(ret != sizeof(int))
		return NULL;
	buffer = calloc(dim, sizeof(char));
	if(buffer == NULL)
		return NULL;
	ret = secure_read(0, buffer, dim, conn);
	if(ret != dim){
		memset(buffer, 0, ret);
		free(buffer);
		return NULL;
	}
	
	*size = dim;
	return buffer;
}

/*
* Authenticates the client and returns the command that he/she wants perform.
* Return NO_AUTH in case of error or bad client password
*/
int authenticate_client(SSL* conn, struct client_ctx* client){
	int dim;
	int ret;
	int dim_pwd;
	unsigned char* username;
	unsigned char* pwd;
	unsigned char* file_name;
	uint8_t cmd;
	
	if(conn == NULL)
		return NO_AUTH;
	//Reads the username	
	username = read_formatted(conn, &dim);
	if(username == NULL){
		return NO_AUTH;
	}
	/*DEBUG*/
	//printf("%s\n", username);
	
	memcpy(client->name, username, (dim < MAX_USR_NAME) ? dim : MAX_USR_NAME);
	
	//Reads the password	
	pwd = read_formatted(conn, &dim_pwd);
	if(pwd == NULL){
		free(username);
		return NO_AUTH;
	}
	/*DEBUG*/
	//printf("%s\n", pwd);
	
	//Checks for the validity of the password
	ret = find_usr_pwd(username, pwd, dim_pwd);
	memset(pwd, 0, dim_pwd);
	free(pwd);
	
	if(ret != 1){
		free(username);
		return NO_AUTH;
	}
	
	//Reads the command
	ret = secure_read(0, &cmd, sizeof(uint8_t), conn);
	if(ret != sizeof(uint8_t)){
		free(username);
		memset(pwd, 0, dim_pwd);
		free(pwd);
		return NO_AUTH;
	}
	/*DEBUG*/
	//printf("%i\n", cmd);
	
	//Reads the file name
	file_name = read_formatted(conn, &dim);
	if(file_name == NULL){
		free(username);
		return NO_AUTH;
	}
	/*DEBUG*/
	//printf("%s\n", file_name); 
	
	memcpy(client->file_name, file_name, (dim < MAX_FILE_NAME) ? dim : MAX_FILE_NAME);
	
	free(file_name);
	free(username);
	return (int)cmd;
}


int disconnect(struct server_ctx* server){
	int ret = SSL_shutdown(server->connection);
	close(server->to_client_sk);
	SSL_free(server->connection);
	return ret;
}


void send_code(SSL* conn, uint8_t code){
	secure_write(0, &code, sizeof(code), conn);
}


/*
* Function that splits the key in N pieces through the "Shamir secret-sharing" algorithm 
* and sends each piece to each peer of Key Storage Service
* Parameter "file_id" is the hash value (SHA256) used as unique id of file
* Return -1 if error occurs
*/
int Secret_sharing(struct server_ctx* server, unsigned char* key, unsigned char* file_id){
	return 1;
}


/*
* Function that collects the key's pieces and reconstructs the key through the "Shamir secret-sharing" algorithm 
* Parameter "file_id" is the hash value (SHA256) used as unique id of file
* Return -1 if error occurs
*/
int Secret_retrieve(struct server_ctx* server, unsigned char** key, unsigned char* file_id){
	return 1;
}


/*
* Update function receives the ciphertext and the key: <size_cipher> <Ek(File || H(File))> <AES256_key>
* stores it in the client's directory and calls the splitting function 
* Returns -1 if error occurs 
*/
int upload(struct server_ctx* server, SSL* conn, struct client_ctx* client){
	FILE* fd;
	int dim;
	int ret;
	unsigned char buffer[BUF_DIM];
	int n_rounds;			//number of read-write cycles
	int last_round;			//number of bytes to transfer at last round 
	int i;
	char* filestore = malloc(strlen(FILE_STORE) + strlen(client->name) + strlen(client->file_name) + 1);
	unsigned char* key;
	unsigned char* file_id;
	
	
	//fetch the client directory
	strcpy(filestore, FILE_STORE);
	strcat(filestore, client->name);
	mkdir(filestore, S_IRWXU);
	
	//create/open the file
	strcat(filestore, "/");
	strcat(filestore, client->file_name);
	fd = fopen(filestore, "w");
	
	if(fd == NULL){
		free(filestore);
		return -1;
	}
	
	//Reads the size of ciphertext
	ret = secure_read(0, &dim, sizeof(int), conn);
	if(ret != sizeof(int))
		return -1; 
	
	n_rounds = dim / BUF_DIM;
	last_round = dim % BUF_DIM;
	
	for(i = 0; i < n_rounds; i++){
		ret = secure_read(0, buffer, BUF_DIM, conn);
		if(ret != BUF_DIM){			//if there is a partial read, add the #bytes not readed at the last round 
             		last_round += BUF_DIM - ret;	//but we are over TCP so there should not be this kind of problem
		}
		
		fwrite(buffer, sizeof(char), ret, fd);	
	}
	//Last round
	ret = secure_read(0, buffer, last_round, conn);
	fwrite(buffer, sizeof(char), ret, fd);
	
	fclose(fd);
	
	//Reads the key, and split it
	key = calloc(KEY_DIM, sizeof(char));
	ret = secure_read(0, key, KEY_DIM, conn);
	
	//Computed the hash of file_name and username
	strcpy(buffer, client->file_name);
	strcat(buffer, client->name);
	file_id = do_hash(buffer, strlen(client->file_name) + strlen(client->name) , NULL);
	
	//Split the key
	ret = Secret_sharing(server, key, file_id);
	
	memset(key, 0, KEY_DIM);
	free(key);
	free(file_id);
	free(filestore);
	
	return ret;
		
}


int dim_of_file(char* namefile){
	struct stat* buff = (struct stat*)malloc(sizeof(struct stat));
	stat(namefile, buff);
	return buff->st_size;
}

/*
* Download function. 
* It checks if the asked file exists, retrieves the key and then sends back the file
* FORMAT OF MESSAGE: <dim><encrypted data>
* Returns -1 if the file doesn't exist or if an error occurs 
*/
int download(struct server_ctx* server, SSL* conn, struct client_ctx* client){
	FILE* fd;
	int dim;
	int ret;
	unsigned char buffer[BUF_DIM];
	int n_rounds;			//number of read-write cycles
	int last_round;			//number of bytes to transfer at last round 
	int i;
	char* filestore = malloc(strlen(FILE_STORE) + strlen(client->name) + strlen(client->file_name) + 1);
	unsigned char* key;
	unsigned char* file_id;
	
	
	//fetch the client directory
	strcpy(filestore, FILE_STORE);
	strcat(filestore, client->name);
	
	//create/open the file
	strcat(filestore, "/");
	strcat(filestore, client->file_name);
	fd = fopen(filestore, "r");
	
	if(fd == NULL){
		send_code(conn, NO_FILE);
		free(filestore);
		return -1;
	}
	
	//Computed the hash of file_name and username
	strcpy(buffer, client->file_name);
	strcat(buffer, client->name);
	file_id = do_hash(buffer, strlen(client->file_name) + strlen(client->name) , NULL);
	
	//Retrieve the key
	ret = Secret_retrieve(server, &key, file_id);
	if(ret == -1){
		send_code(conn, NO_FILE);
		free(filestore);
		fclose(fd);
		return -1;
	}
	
	//Read the dimension of file
	dim = dim_of_file(filestore);
	
	//Send the dimention of file
	ret = secure_write(0, &dim, sizeof(int), conn);
	if(ret != sizeof(int)){
		send_code(conn, NO_FILE);
		free(filestore);
		fclose(fd);
		return -1;
	}
	
	
	n_rounds = dim / BUF_DIM;
	last_round = dim % BUF_DIM;
	
	for(i = 0; i < n_rounds; i++){
		ret = fread(buffer, sizeof(char), BUF_DIM, fd);
		if(ret != BUF_DIM){			 
             		last_round += BUF_DIM - ret;
		}
		
		ret = secure_write(0, buffer, ret, conn);	
	}
	//Last round
	ret = fread(buffer, sizeof(char), last_round, fd);	
	ret = secure_write(0, buffer, ret, conn);
	
	fclose(fd);
	
	//Sends the key
	ret = secure_write(0, key, KEY_DIM, conn);
	
	memset(key, 0, KEY_DIM);
	
	free(key);
	free(file_id);
	free(filestore);
	return ret;
}

int main(int argc, char* argv[]){
	int ret;
	struct server_ctx server;
	struct client_ctx client;
	int end = 1;
	
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
	while(end){
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
		/*---------------------------THE PROTOCOL-------------------------------*/
		
		
		ret = authenticate_client(server.connection, &client);
		
		if(ret != -1){
			printf("Client %s authenticated, file name: %s\n", client.name, client.file_name);
			send_code(server.connection, AUTH_OK);
		}
		
		switch(ret){
			case UPLOAD:
				ret = upload(&server, server.connection, &client);
				
				if(ret != 1)
					send_code(server.connection, UPDATE_FAIL);
				else
					send_code(server.connection, UPDATE_OK);
				disconnect(&server);								
				break;
			case DOWNLOAD:
				ret = download(&server, server.connection, &client);
				/*
				if(ret != 1)
					send_code(server.connection, DOWNLOAD_FAIL);
				*/
				disconnect(&server);
				break;
			
			/*Authentication failed or errors occur*/	
			default:
			case NO_AUTH:
				printf("Client %s authentication failed\n", client.name);
				send_code(server.connection, AUTH_FAIL);
				disconnect(&server);
				break;
		}
	}	
	
	server_cleanup(&server);
	exit(0);
}
