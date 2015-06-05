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
#include <sys/select.h>
#include "Shamir_sharing.h"
#include <errno.h>

/*---------CONSTANTS--------------*/
#define PUB_KEY_PATH 		"./Certs/keyserver_pubkey"
#define FILE_STORE 		"./File_store/"
#define BUF_DIM 		1024
#define HASH_DIM 		EVP_MD_size(EVP_sha256())
#define KEY_DIM 		EVP_CIPHER_key_length(EVP_aes_256_cbc())
#define MAX_USR_NAME 		20
#define MAX_FILE_NAME 		20
#define SHARING_KEY_PORT 	5555
#define MAX_CON 		10
#define SERVER_ID 		1

/*---------ERROR MESSAGES---------*/
#define AUTH_FAIL 	0
#define AUTH_OK 	1
#define NO_FILE 	2
#define UPDATE_FAIL 	0
#define UPDATE_OK 	1
#define NO_SECRET	3

/*---------COMMAND MESSAGES-------*/
#define NO_AUTH 	-1
#define UPLOAD 		1
#define DOWNLOAD 	2
#define UP_KEY 		1
#define DOWN_KEY	2


//Server context
struct server_ctx{
	int server_sk;				//Listening socket for client connection
	int to_client_sk;			//Socket used for client communications
	int sharing_sk;				//Listening socket for key-server connection
	int key_server[MAX_CON];		//Array of sockets for key-server communications
	unsigned char* session_key[MAX_CON];	//Array of buffer for key-server session keys 
	int index;				//Index for the arrays
	
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

void print_bytes_debug(unsigned char* buf, int len) {
  int i = 0;
  for (i = 0; i < len - 1; i++)
    printf("%02X:", buf[i]);
  printf("%02X", buf[len - 1]);
  printf("\n");
}


void help(){
	char* options_msg = "Usage: Files_server <ip address> <port number>\n\
	[Optionals:] <certificate path> <private key path>\n";
        
	printf("%s", options_msg);		
}

//restituisce il descrittore del socket server
int create_socket(char* address, int port){
	int ret;
	int lst_sk;		//socket del server
	int optval;
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
	optval = 1;
	setsockopt(lst_sk, SOL_SOCKET,SO_REUSEADDR, &optval, sizeof(optval));
	//lego l'indirizzo al socket
	ret = bind(lst_sk, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret == -1){
		printf("Error in socket bind");
		exit(-1);	
	}
	
	//mi pongo in ascolto sulla porta
	ret = listen(lst_sk, SOMAXCONN);
	if(ret == -1){
		printf("Error in listen");
		exit(-1);	
	}
	
	return lst_sk;
}


//si pone in ascolto di connessioni dal client, le accetta e restituisce il socket creato per lo scambio dati
int accept_client(int server_sk){
	int client_addr_len;
	int com_sk;
	struct sockaddr client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	//attendo nuove connessioni da parte dei client
	//client_addr_len = sizeof(client_addr);
	com_sk = accept(server_sk, NULL, NULL);
	if(com_sk == -1){
		printf("Error in accept: %s\n", strerror(errno));
		exit(-1);	
	}
	return com_sk;
}

//funzione che libera tutte le strutture dati del server
void server_cleanup(struct server_ctx* server){
	int i;
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
	if(server->sharing_sk != 0)
		close(server->sharing_sk);
	if(server->ssl_factory != NULL)
		SSL_CTX_free(server->ssl_factory);
	for(i = 0; i < MAX_CON; i++){
		if(server->key_server[i] != 0)
			close(server->key_server[i]);
		if(server->session_key[i] != NULL){
			memset(server->session_key[i], 0, KEY_DIM);
			free(server->session_key[i]);
		}
	}
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
	printf("readed string: %.*s len: %i\n", dim, (char*)buffer, dim);
	if(ret != dim){
		memset(buffer, 0, ret);
		free(buffer);
		return NULL;
	}
	
	*size = dim;
	return buffer;
}

/*
* Writes the messages in format <size>||<buffer> in the socket
* Returns the number of bytes written in the socket
* or -1 if an error occurs 
*/
int write_formatted(int socket, unsigned char* buffer, int size){
	int ret;
	if(socket < 0 || buffer == NULL || size <= 0)
		return -1;
	ret = write(socket, &size, sizeof(int));
	if(ret != sizeof(int))
		return -1;
	ret = write(socket, buffer, size);
	if(ret != size)
		return -1;
	return ret;
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
	client->name[(dim < MAX_USR_NAME) ? dim : MAX_USR_NAME] = '\0';
	
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
	client->file_name[(dim < MAX_FILE_NAME) ? dim : MAX_FILE_NAME] = '\0';
	free(file_name);
	free(username);
	return (int)cmd;
}


int disconnect(struct server_ctx* server){
	int ret = 0;
	ret += SSL_shutdown(server->connection);
	ret += close(server->to_client_sk);
	SSL_free(server->connection);
	
	return (ret < 0) ? -1 : 0;
}


void send_code(SSL* conn, uint8_t code){
	secure_write(0, &code, sizeof(uint8_t), conn);
}


/*
* Function that splits the key in N pieces through the "Shamir secret-sharing" algorithm 
* and sends each piece to each peer of Key Storage Service
* Parameter "file_id" is the hash value (SHA256) used as unique id of file
* Return -1 if error occurs
*/
int Secret_splitting(struct server_ctx* server, unsigned char* key, unsigned char* file_id){
	struct secret_pieces* shares;
	int n_peers;
	int needed;
	int i;
	unsigned char* ciphertext;
	unsigned char* message;
	unsigned char plaintext[BUF_DIM];
	unsigned char* hash;
	int dim_plaintext = 0;
	int dim_ciphertext = 0;
	int ret;
	int temp = 0;
	uint8_t cmd = UP_KEY;
	int counter = 0;
	
	if(server == NULL || key == NULL || file_id == NULL)
		return -1;
	
	n_peers = server->index;
	if(n_peers == 0){
		printf("Key Storage Service is down! No peers are connected.\n");
		return -1;
	}
	//Only the half pieces are needed to reconstruct the key
	needed = (n_peers == 1) ? n_peers : n_peers/2;
	
	//Split the key in 'n_peers' pieces
	shares = secret_sharing(key, KEY_DIM, n_peers, needed);
	
	//Now send the shares. One to every connected peers.
	for(i = 0; i < n_peers; i++){
		temp = 0;
		//Encrypt the command
		ciphertext = sym_crypt(&cmd, sizeof(cmd), server->session_key[i], &dim_ciphertext);
		if(ciphertext == NULL){
			continue;
		}
		//Send <dim><Ek(CMD)>
		ret = write_formatted(server->key_server[i], ciphertext, dim_ciphertext);
		free(ciphertext);
		if(ret == -1){
			close(server->key_server[i]);
			server->key_server[i] = 0;
			server->session_key[i] = NULL;
			continue;
		}
		
		/*DEBUG*/
		printf("X = %i\n", shares[i].x);
		print_bytes_debug(shares[i].piece, shares[i].dim_piece);
		
		//Build the message <hash_file_id> <X> <Dim_share> <Share> <Hash(payload)>
		dim_plaintext = 2*sizeof(int) + shares[i].dim_piece + 2*HASH_DIM;
		memcpy(plaintext + temp, file_id, HASH_DIM);	 		//<Hash_file_id>
		temp += HASH_DIM;
		memcpy(plaintext + temp, &shares[i].x, sizeof(int));		//<X>
		temp += sizeof(int);
		memcpy(plaintext + temp, &shares[i].dim_piece, sizeof(int));	//<Dim_share>
		temp += sizeof(int);
		memcpy(plaintext + temp, shares[i].piece, shares[i].dim_piece);	//<Share>
		temp += shares[i].dim_piece;
		hash = do_hash(plaintext, temp, NULL);				//Computes the hash of the payload
		memcpy(plaintext + temp, hash, HASH_DIM);			//Concatenates the hash with the message
		temp += HASH_DIM;
		
		
		//Encrypt the message with i-th session key		
		ciphertext = sym_crypt(plaintext, dim_plaintext, server->session_key[i], &dim_ciphertext);
		if(ciphertext == NULL){
			free(hash);
			continue;
		}
		//Send the envelope = <dim_ciphertext><ciphertext>
		ret = write_formatted(server->key_server[i], ciphertext, dim_ciphertext);
		if(ret == -1){
			free(ciphertext);
			free(hash);
			close(server->key_server[i]);
			server->key_server[i] = 0;
			server->session_key[i] = NULL;
			continue;
		}
		free(hash);
		free(ciphertext);
		counter++;
	}
	memset(shares, 0, sizeof(struct secret_pieces) * n_peers);
	free(shares);
	if(counter < needed)				//If i have sent a number of secret pieces less than the needed, the splitting has failed
		return -1;
	return 1;
}


/*
* Function that collects the key's pieces and reconstructs the key through the "Shamir secret-sharing" algorithm 
* Parameter "file_id" is the hash value (SHA256) used as unique id of file
* Return -1 if error occurs
*/
int Secret_retrieve(struct server_ctx* server, unsigned char** key, unsigned char* file_id){
	int ret;
	uint8_t cmd = DOWN_KEY;
	uint8_t no_secret = NO_SECRET;
	int i;
	int n_peers;
	int dim_ciphertext;
	unsigned char* ciphertext;
	int dim_plaintext;
	unsigned char* plaintext;
	struct secret_pieces* shares;
	int n_response = 0;
	
	//Checks
	if(server == NULL || key == NULL || file_id == NULL)
		return -1;
	
	n_peers = server->index;
	if(n_peers == 0){
		printf("Key Storage Service is down! No peers are connected.\n");
		return -1;
	}
	shares = malloc(sizeof(struct secret_pieces) * n_peers);
	
	for(i = 0; i < n_peers; i++){
		if(server->session_key[i] == NULL || server->key_server[i] <= 0)
			continue;
		//Encrypt the command
		ciphertext = sym_crypt(&cmd, sizeof(cmd), server->session_key[i], &dim_ciphertext);
		if(ciphertext == NULL){
			continue;
		}
		//Send <dim><Ek(CMD)>
		ret = write_formatted(server->key_server[i], ciphertext, dim_ciphertext);
		free(ciphertext);
		if(ret == -1){
			close(server->key_server[i]);
			server->key_server[i] = 0;
			server->session_key[i] = NULL;
			continue;
		}
		
		
		//Encrypt the <file_id>
		ciphertext = sym_crypt(file_id, HASH_DIM, server->session_key[i], &dim_ciphertext);
		if(ciphertext == NULL){
			continue;
		}
		//Send <dim><Ek(file_id)>
		ret = write_formatted(server->key_server[i], ciphertext, dim_ciphertext);
		free(ciphertext);
		if(ret == -1){
			close(server->key_server[i]);
			server->key_server[i] = 0;
			server->session_key[i] = NULL;
			continue;
		}
		
		//Read the response
		ret = read(server->key_server[i], &dim_ciphertext, sizeof(int));
		if(ret != sizeof(int)){
			close(server->key_server[i]);
			server->key_server[i] = 0;
			server->session_key[i] = NULL;
			continue;
		}		
		ciphertext = malloc(dim_ciphertext);
		ret = read(server->key_server[i], ciphertext, dim_ciphertext);
		if(ret != dim_ciphertext){
			memset(plaintext, 0, dim_plaintext);
			free(plaintext);
			free(ciphertext);
			continue;
		}
		//Decrypt the message
		plaintext = sym_decrypt(ciphertext, dim_ciphertext, server->session_key[i], &dim_plaintext);
		free(ciphertext);
		//Check the type of the message
		if(dim_plaintext == sizeof(uint8_t) && *plaintext == no_secret){
			free(plaintext);
			continue;
		}
		//Check	the integrity of the content
		ret = verify_hash(plaintext, dim_plaintext - HASH_DIM, NULL, plaintext + (dim_plaintext - HASH_DIM));
		if(ret != 1){
			memset(plaintext, 0, dim_plaintext);
			free(plaintext);
			continue;
		}
		//NOTE: message format <file_id> <X> <Dim_share> <Share>
		//Check if the file_id is the same
		ret = CRYPTO_memcmp(plaintext, file_id, HASH_DIM);
		if(ret != 0){
			memset(plaintext, 0, dim_plaintext);
			free(plaintext);
			continue;
		}
		//If we are here the piece of secret is related to the file that we are looking for, and its integrity is fine
		//Thus, copy in the secret_pieces struct the piece of secret 
		memcpy(&shares[n_response].x, plaintext + HASH_DIM, sizeof(int));
		memcpy(&shares[n_response].dim_piece, plaintext + HASH_DIM + sizeof(int), sizeof(int));
		shares[n_response].piece = malloc(shares[n_response].dim_piece);
		memcpy(shares[n_response].piece, plaintext + HASH_DIM + sizeof(int) + sizeof(int), shares[n_response].dim_piece);
		
		/*DEBUG*/
		printf("X = %i\n", shares[n_response].x);
		printf("DIM = %i\n", shares[n_response].dim_piece);
		printf("Piece =");
		print_bytes_debug(shares[n_response].piece, shares[n_response].dim_piece);
		printf("\n");
		
		n_response++;
		memset(plaintext, 0, dim_plaintext);
		free(plaintext);	
	}
	
	if(n_response == 0){
		free(shares);
		return -1;
	}
	
	*key = secret_recovery(shares, n_response, &dim_ciphertext);
	
	memset(shares, 0, sizeof(struct secret_pieces) * n_peers);
	free(shares);
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
	file_id = do_hash(buffer, strlen(client->file_name) + strlen(client->name) , filestore);
	
	//Split the key
	ret = Secret_splitting(server, key, file_id);
	
	
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
	file_id = do_hash(buffer, strlen(client->file_name) + strlen(client->name) , filestore);
	
	//Retrieve the key
	ret = Secret_retrieve(server, &key, file_id);
	if(ret == -1){
		send_code(conn, NO_FILE);
		free(filestore);
		fclose(fd);
		return -1;
	}
	
	//Sends the key
	ret = secure_write(0, key, KEY_DIM, conn);
	printf("Arrivato a linea 725 ret = %i\n", ret);
	memset(key, 0, KEY_DIM);
	
	free(key);
	
	//Read the dimension of file
	dim = dim_of_file(filestore);
	
	//Send the dimention of file
	ret = secure_write(0, &dim, sizeof(int), conn);
	if(ret != sizeof(int)){
		printf("Arrivato a linea 736\n");
		send_code(conn, NO_FILE);
		free(filestore);
		fclose(fd);
		return -1;
	}
	
	printf("Arrivato a linea 742\n");
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
	printf("Arrivato a linea 757\n");
	fclose(fd);
	
	free(file_id);
	free(filestore);
	return 1;
}


char* pub_key_path(char* base, int x){
	int dim = (x > 9)? 2 : 1;
	char* temp = malloc(dim);
	char* end = ".pem";
	char* ret;
	
	
	sprintf(temp, "%i", x);
	
	ret = malloc(strlen(base) + strlen(temp) + strlen(end) + 1);
	strcpy(ret, base);
	strcat(ret, temp);
	strcat(ret, end);
	free(temp);
	return ret;
}

/*
* Function that establish a session key with a key-server 
* It returns the session key, or NULL if an error occurs
*/
unsigned char* key_estab_protocol(int socket){
	unsigned char* session_key;
	unsigned char buffer[BUF_DIM];
	unsigned char* plaintext;
	unsigned char* nonce;
	unsigned char* ciphertext; 
	char* public_key;
	int EXPECTED_DIM[] = {12, 48, 4};		//Expected size of messages 
	int ret;
	int dim;
	int outlen;
	int receiver_id;
	
	
	/*---------- Read M1 P->S {S, P, Np}ks+ --------------*/
	ret = read(socket, &dim, sizeof(int));
	if(ret != sizeof(int))
		goto error;
	ret = read(socket, buffer, dim);
	if(ret != dim)
		goto error;
	//Decrypt it
	plaintext = asym_decrypt(buffer, dim, &outlen, "./Certs/fileserver_private.pem");
	if(outlen != EXPECTED_DIM[0])
		goto error;
		
	/*DEBUG*/
	printf("-------->Received M1: %i, %i, %i\n", (int)*plaintext, (int)*(plaintext + 4), (int)*(plaintext + 8));
	
	//Checks if the first field "S" is equal to Server ID
	memcpy(&ret, plaintext, sizeof(int));
	if(ret != SERVER_ID)
		goto error;
	memcpy(&receiver_id, plaintext + sizeof(int), sizeof(int));
	//Create the public key path associated to the key server
	public_key = pub_key_path(PUB_KEY_PATH, receiver_id);
	
	/*----------- Send M2 S->P {S, P, Np, Ns, K}kp+ ---------*/
	memcpy(buffer, plaintext, outlen);
	//Clear the 'plaintext' buffer
	memset(plaintext, 0, outlen);
	free(plaintext);
	plaintext = NULL;
	//Generate the nonce of 4 byte
	nonce = malloc(4);
	if(nonce == NULL)
		goto error;
	ret = RAND_bytes(nonce, 4);
	if(ret != 1)
		goto error;
	//Generate the AES256 key
	session_key = malloc(KEY_DIM);
	if(session_key == NULL)
		goto error;
	ret = RAND_bytes(session_key, KEY_DIM);
	if(ret != 1)
		goto error;	
	memcpy(buffer + outlen, nonce, 4);
	memcpy(buffer + outlen + 4, session_key, KEY_DIM);
	
	/*DEBUG*/
	printf("-------->Sent M2: %i, %i, %i, %i\n", (int)*buffer, (int)*(buffer + 4), (int)*(buffer + 8), (int)*(buffer + 12));
	
	//Encrypt the message with the receiver's public key
	printf("%s\n", public_key);
	ciphertext = asym_crypto(buffer, outlen + 4 + KEY_DIM, &outlen, public_key);
	if(ciphertext == NULL)
		goto error;
	//Send the encrypted message and its dimension
	ret = write(socket, &outlen, sizeof(int));
	if(ret != sizeof(int))
		goto error;
	ret = write(socket, ciphertext, outlen);
	if(ret != outlen)
		goto error;
	//Clear the buffer
	
	/*----------- Read M3 P->S {Ns}k ------------*/
	ret = read(socket, &dim, sizeof(int));
	if(ret != sizeof(int))
		goto error;
	ret = read(socket, buffer, dim);
	if(ret != dim)
		goto error;
	//Decrypt the ciphertext with K
	plaintext = sym_decrypt(buffer, dim, session_key, &outlen);
	if(outlen != EXPECTED_DIM[2])
		goto error;
	
	/*DEBUG*/
	printf("-------->Received M3: %i\n", (int)*plaintext);
	
	ret = CRYPTO_memcmp(plaintext, nonce, 4);
	if(ret != 0)
		goto error;
	/*----------- If we are here, everything was fine, thus clean all buffers and return the session key ------*/
	
	memset(plaintext, 0, outlen);
	free(plaintext);
	memset(nonce, 0, 4);
	free(nonce);
	memset(buffer, 0, BUF_DIM);
	free(ciphertext);
	free(public_key);
	/*DEBUG*/
	printf("Established key: ");
	print_bytes_debug(session_key, KEY_DIM);
	
	return session_key;
error:
	if(session_key != NULL){
		memset(session_key, 0, KEY_DIM);
		free(session_key);
	}
	
	memset(buffer, 0, BUF_DIM);
	
	if(plaintext != NULL){
		free(plaintext);
	}
	if(nonce != NULL){
		memset(nonce, 0, 4);
		free(nonce);
	}
	if(ciphertext != NULL){
		free(ciphertext);
	}
	return NULL;	
}


/*
* This function performs the select operation for handle the client connections 
* and key server connections, simultaneously
* It returns 1 if there is a key-server connection, 0 if there is a client connection, -1 if an error occurs
*/
int do_select(struct server_ctx* server){
	fd_set selectfds;
    	int max_fds = 0;
    	int ret;
	
	FD_ZERO(&selectfds);

	FD_SET(server->server_sk, &selectfds);
	FD_SET(server->sharing_sk, &selectfds);
	max_fds = (server->server_sk > server->sharing_sk) ? server->server_sk : server->sharing_sk;

        ret = select(FD_SETSIZE, &selectfds, NULL, NULL, NULL);
        
        if(ret < 0)
        	return -1;
        if(FD_ISSET(server->sharing_sk, &selectfds))		//Gives more priority to key_server connections
        	return 1;
        else if(FD_ISSET(server->server_sk, &selectfds))
        	return 0;
        else 
        	return -1;
}

/*
* Given the connect request from the key_server, it runs the key establishment protocol and open the connection 
* with that server
*/
void connect_key_server(struct server_ctx* server){
	int sock_temp;
	
	//Accept connection from the key-server
	sock_temp = accept_client(server->sharing_sk);
	//Add the socket to the server context
	if(server->index == MAX_CON){
		close(sock_temp);
		return;
	}
	server->key_server[server->index] = sock_temp;
	server->index++;
	
	printf("\n\nKey Server %i connected, start the key establishment protocol\n", server->index-1);
	
	/*---------KEY ESTABLISHMENT PROTOCOL---------*/
	server->session_key[server->index-1] = key_estab_protocol(sock_temp);
	if(server->session_key[server->index-1] == NULL){		//The handshake didn't go fine
		close(server->key_server[server->index]);
		server->key_server[server->index] = 0;
		server->index--;
		printf("Key establishment protocol result: FAILED\n");
	}
	else
		printf("Key establishment protocol result: OK\n");
	return;
}

int main(int argc, char* argv[]){
	int ret;
	struct server_ctx server;
	struct client_ctx client;
	int end = 1;
	
	memset(&server, 0, sizeof(struct server_ctx));
	memset(&client, 0, sizeof(struct client_ctx));
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
				
	//create the client-listening socket 
	server.server_sk = create_socket(server.address, server.port);
	
	//create the key-sharing-server socket
	server.sharing_sk = create_socket(server.address, SHARING_KEY_PORT);
	
	while(end){
		
		//Wait for client connections or key-server connection
		ret = do_select(&server);
		if(ret == -1){
			printf("Error in select function\n");
			server_cleanup(&server);
			exit(-1);
		}
		else if(ret == 1){
			printf("Key-Server conneted, handshake in course\n");
			connect_key_server(&server);
		}
		else{			
			//connect with the client
			server.to_client_sk = accept_client(server.server_sk);
			printf("\n\nClient conneted, authentication in course\n");
			
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
			/*---------------------------THE PROTOCOL with client-------------------------------*/
		
		
			ret = authenticate_client(server.connection, &client);
		
			if(ret != -1){
				printf("Client %s authenticated, file name: %s\n", client.name, client.file_name);
				send_code(server.connection, AUTH_OK);
			}
		
			switch(ret){
				case UPLOAD:
					ret = upload(&server, server.connection, &client);
					
					if(ret != 1)
						printf("Upload fail\n");
						//send_code(server.connection, UPDATE_FAIL);
					else
						printf("Upload ok\n");
						//send_code(server.connection, UPDATE_OK);
					
					disconnect(&server);								
					break;
				case DOWNLOAD:
					ret = download(&server, server.connection, &client);
					
					if(ret != 1)
						printf("Download fail\n");
						//send_code(server.connection, DOWNLOAD_FAIL);
					else
						printf("Download ok\n");
					disconnect(&server);
					break;
			
				/*Authentication failed or errors occur*/	
				default:
				case NO_AUTH:
					printf("Client %s authentication failed\n", client.name);
					if(SSL_get_shutdown(server.connection) != SSL_RECEIVED_SHUTDOWN)
						send_code(server.connection, AUTH_FAIL);
					disconnect(&server);
			
			}//End switch
		}//End if
	}//End while
	
	server_cleanup(&server);
	exit(0);
}
