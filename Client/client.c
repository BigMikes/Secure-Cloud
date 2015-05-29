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

/*void symmetric_encrypt_send(SSL* connection, char* file_name, unsigned char* key, int key_len){
	///////////////////////////
	//dopo ogni update vale la pena di fare la check_ret(outlen, (int passato))  ???
	///////////////////////////
	
	//generic
	int ret;
	unsigned char buffer[DIM_BUFFER];
	FILE* fd;
	int readed_byte;
	
	//encrypt
	EVP_CIPHER_CTX* ctx;
	unsigned char ciphertex[DIM_BUFFER];
	int outlen = 0;
	
	//hash
	EVP_MD_CTX sha_ctx;
	unsigned int digest_size = 32;  /////////////////////// penso che sia definita da qualche parte 
	unsigned char hash[digest_size];

	
	///////////// i dati dovrebbero già essere tutti stati controllati giusto??
	
	//open file
	fd = fopen(file_name, "r");
	if(fd == NULL){
		printf("Impossible to open %s file\n", file_name);
		exit(EXIT_FAILURE);
	}
	
	//encrypt initialization
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));	
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx, SYM_CIPHER, key, NULL);
	
	//hash initialization
	EVP_MD_CTX_init(&sha_ctx);
	EVP_DigestInit(&sha_ctx, EVP_sha256());
	
	//send dimension
	struct stat st;
	stat(file_name, &st); // file size = st.st_size
	int tmp = ((st.st_size + digest_size)/ EVP_CIPHER_block_size(SYM_CIPHER)) + 1;
	tmp *= EVP_CIPHER_block_size(SYM_CIPHER);
	printf("Dim = %i\n", tmp);
	ret = secure_write(0, &tmp, sizeof(int), connection); 
	check_ret(ret, sizeof(int));
	
	//read until end of file
	//for each read update encrypt and hash
	while( 1 ){
		
		readed_byte = fread(buffer, sizeof(char), DIM_BUFFER, fd);
		if(readed_byte == -1){
			printf("Error");
			exit(EXIT_FAILURE);
		}
		
		if(readed_byte == 0){	//nel caso in cui la dimensione del file è multipla di dim_buffer
			break;
		}
		
		//Encrypt Update
		EVP_EncryptUpdate(ctx, ciphertex, &outlen, buffer, readed_byte);
		
		//hash update
		EVP_DigestUpdate(&sha_ctx, buffer, readed_byte);
		
		//send encrypted data at this step
		printf("testo inviato: %.*s\n", outlen, ciphertex);
		ret = secure_write(0, ciphertex, outlen, connection); 
		check_ret(ret, outlen);
		
		if(readed_byte != DIM_BUFFER){
			break;
		}
	}
	
	//hashfinal; also clear ctx
	EVP_DigestFinal(&sha_ctx, hash, &digest_size);
	
	
	//encrypt update the hash
	EVP_EncryptUpdate(ctx, ciphertex, &outlen, hash, digest_size);
	ret = secure_write(0, ciphertex, outlen, connection); 
	check_ret(ret, outlen);
	
	//EVP_EncryptFinal(); also close ctx so no need for EVP_CIPHER_CTX_cleanup(ctx);
	ret = EVP_EncryptFinal(ctx, ciphertex, &outlen);
	if(ret == 0)
		exit(EXIT_FAILURE);
	ret = secure_write(0, ciphertex, outlen, connection); 
	check_ret(ret, outlen);
	
	//close
	free(ctx);
	fclose(fd);
}*/

/*void symmetric_decrypt_receive(SSL* connection, char* file_name, unsigned char* key, int key_len){
	//variabili
	int ret, tmp;
	int file_len;
	int readed_byte = 0;
	unsigned char buffer[DIM_BUFFER];
	FILE* fd;
	
	//variabili decifratore
	EVP_CIPHER_CTX* ctx;
	unsigned char plaintex[DIM_BUFFER];
	int outlen = 0;
	
	//variabili hash
	EVP_MD_CTX sha_ctx;
	unsigned int digest_size = 32;  //////////////////////// penso che sia definita da qualche parte 
	unsigned char hash[digest_size];
	unsigned char old_hash[digest_size];
	
	//inizializzo il descrittore di file
	fd = fopen(file_name, "w");
	if(fd == NULL){
		printf("Impossible to open %s file\n", file_name);
		exit(EXIT_FAILURE);
	}
	
	//inizializzo decifratore
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));	
	EVP_CIPHER_CTX_init(ctx);
	EVP_DecryptInit(ctx, SYM_CIPHER, key, NULL);
	
	//inizializzo hash
	EVP_MD_CTX_init(&sha_ctx);
	EVP_DigestInit(&sha_ctx, EVP_sha256());
	
	//leggo la dimensione del file
	ret = secure_read(0, &file_len, sizeof(int), connection);
	check_ret(ret, sizeof(int));
	
	//inizio la lettura del file a blocchi
	int stop = 1;
	while( stop ){
		if( (readed_byte + DIM_BUFFER) < (file_len - digest_size)){
			ret = secure_read(0, buffer, DIM_BUFFER, connection);
		} else {
			ret = secure_read(0, buffer, (file_len - digest_size - readed_byte), connection);
			stop = 0;
		}
		
		//aggiorno readed byte
		readed_byte += ret;
		
		//adesso in buffer ci sono ret caratteri
		//Decrypt update
		EVP_DecryptUpdate(ctx, plaintex, &outlen, buffer, ret);
		
		//hash update
		EVP_DigestUpdate(&sha_ctx, buffer, ret);
		
		//write plaintext
		tmp = fwrite(plaintex, sizeof(char), ret, fd);
		check_ret(tmp, ret); 
	}
	
	//read hash
	ret = secure_read(0, old_hash, digest_size, connection);
	
	//evaluate new hash
	EVP_DigestFinal(&sha_ctx, hash, &digest_size);
	
	//verify hash
	if(CRYPTO_memcmp(old_hash, hash, digest_size) != 0){
		printf("Corrupted file.\n\n");
		exit(EXIT_FAILURE);
	}
	
	//finalize decrypt
	ret = EVP_DecryptFinal(ctx, plaintex, &outlen);
	if(ret == 0)
		exit(EXIT_FAILURE);
	tmp = fwrite(plaintex, sizeof(char), outlen, fd);
	check_ret(tmp, ret); 
	
	//close
	free(ctx);
	fclose(fd);
}*/

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
	printf("Connection succefully\n");
	
	////body
	printf("Username:\n");
	ret = scanf("%s", username);
	dim_username = strlen(username);
	printf("user: %s len: %i \n", username, dim_username);
	
	printf("\nPassword:\n");
	ret = scanf("%s", password);
	dim_password = strlen(password);
	printf("password: %s len: %i\n", password, dim_password);
	
	printf("\n Operation Upload or Download (u/d):\n");
	support = (char)getchar();
	support = (char)getchar();
	printf("Command: %c\n", support);
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
			printf("Error");
			exit(-1);
	}
	
	printf("\nFile name:\n");
	ret = scanf("%s", file_name);
	dim_file_name = strlen(file_name);
	printf("File: %s len: %i\n", file_name, dim_file_name);
	
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
	
	
	if(command == CMD_UPLOAD){
		//UPLOAD

		//wait for response
		ret = secure_read(0, &server_response, sizeof(uint8_t), connection);
		check_ret(ret, sizeof(uint8_t));
		if(server_response == 0){
			printf("Connection refused.\n");
			exit(-1);
		}
		printf("print something\n");
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
		check_ret(ret, 4);
	
		//wait for response
		ret = secure_read(0, &server_response, sizeof(uint8_t), connection);
		check_ret(ret, sizeof(uint8_t));
		
		//clear 
		memset(cipher_file, 0, cipher_file_len);
		free(cipher_file);
		memset(key, 0, key_len);
		free(key);
	} else {
		//DOWNLOAD
		
		//variabili
		unsigned char* key;
		int key_len;
		
		//read key
		key_len = EVP_CIPHER_key_length(SYM_CIPHER);
		key = (unsigned char*)malloc(key_len);
		ret = secure_read(0, &key, key_len, connection);
		check_ret(ret, key_len);
		
		//read Ek(file || H(file))
		//symmetric_decrypt_receive(connection, file_name, key, key_len);
		
		int cipher_len;
		unsigned char* cipher_buff;
		//read file size
		ret = secure_read(0, &cipher_len, sizeof(int), connection);
		check_ret(ret, sizeof(int));
		
		//read file
		cipher_buff = malloc(cipher_len);
		if(cipher_buff == NULL)
			exit(-1);
		ret = secure_read(0, cipher_buff, cipher_len, connection);
		if(ret != cipher_len){
			memset(cipher_buff, 0, ret);
			free(cipher_buff);
			exit(-1);
		}
		
		//decrypt
		int plain_len;
		char* plain = sym_decrypt(cipher_buff, cipher_len, key, &plain_len);
		
		//write to file
		FILE* output = fopen(file_name, "w");
		if(output == NULL){
			printf("Impossible to write file");
			exit(-1);
		}
		ret = fwrite(plain, sizeof(char), plain_len, output);
		check_ret(ret, plain_len);
		fclose(output);
		
		//clear
		memset(cipher_buff, 0, cipher_len);
		free(cipher_buff);
		free(plain);
		memset(key, 0, key_len);
		free(key);
	}
	
	
	/////////////////////////////////////////////////////////////////////cleanup
	if(-1 == close(socketS)){
		printf("Error in closing operation.\n");
	}
	
	ssl_context_cleanup(ssl_factory);
	return 0;
}
