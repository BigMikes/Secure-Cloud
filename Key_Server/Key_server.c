#include "../security_ssl.h"
#include "../utils.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>

#define UPLOAD_KEY 1
#define DOWNLOAD_KEY 2
#define N_ELEMENTS 15	//numero di elementi che il server è in grado di gestire

struct secret_piece_s{
	unsigned char id[32];
	int x;
	int dim_secret;
	unsigned char* secret;
};
typedef struct secret_piece_s secret_piece_t;


void CloseSocket(int sock){
  close(sock);
  return;
}

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
		exit(-1);
	}
	return lst_sk;
}

void send_msg(int sock, void* Messaggio, int count){
	//for debug
	//printf("Client send: %s\n", (char*)Messaggio);
  
	if (write(sock, Messaggio, count) < 0){
		printf("Impossibile mandare il messaggio.\n");
		CloseSocket(sock);
		exit(1);
	}  
}

void recv_msg(int sock, void* Messaggio, int count){
	if (read(sock, Messaggio, count) < 0)
	{
		printf("Impossibile ricevere il messaggio.\n");
		CloseSocket(sock);
		exit(1);
	}
	//for debug
	//printf("Messaggio ricevuto con successo: %s\n", (char*)Messaggio);
}

unsigned char* generate_nonce(int len){
	unsigned char* nonce = (unsigned char*)malloc(len);
	int ret = RAND_bytes(nonce, len);
	if(ret == 0){
		printf("error in nonce generation");
		exit(-1);
	}
	return nonce;
}

void print_unsigned_char(unsigned char* msg, int len){
	int i;
	for(i = 0 ; i < len ; i++)
		printf("%02x", msg[i]);
}

void print_secrets(secret_piece_t* secrets, int len){
	int i;
	printf("Secrets\n");
	for(i = 0 ; i < len ; i++){
		printf("Blocco %i--------------------------\n", i);
		if(secrets[i].secret != NULL){
			printf("id:\t\t"); print_unsigned_char(secrets[i].id, 32); printf("\n");
			printf("x:\t\t%i\n", secrets[i].x);
			printf("dim_secret:\t%i\n", secrets[i].dim_secret);
			printf("secret:\t\t"); print_unsigned_char(secrets[i].secret, secrets[i].dim_secret); printf("\n");
		}
	}
	printf("----------------------------------\n");
}

/*
 * argomenti
 * 	indirizzo server
 * 	porta server 
 * 	server number
 * 	[public file server key]
 * 	[private key]
 */
int main(int argc, char* argv[]) {
	//variabili
	int i;
	unsigned char* hash = (unsigned char*)malloc(32);
	
	int my_server_number;
	int file_server_id;
	char* addr;
	int port;
	char* file_server_pub_key;
	char* private_key;
	int socketF;
	
	unsigned char* msg;
	int msg_len;
	
	int enc_msg_len;
	unsigned char* enc_msg;
	
	unsigned char* noncep;
	unsigned char* nonces;
	int nonce_len = 4;
	
	unsigned char* shared_key;
	
	secret_piece_t secrets[N_ELEMENTS];
	int next_elem;
	
	uint8_t up_key = 1;
	uint8_t down_key = 2;
	
	//controlli
	if(argc < 4) {
		printf("Errore nel passaggio dei parametri\n");
		return -1;
	}
	
	//inizializzazioni
	addr = argv[1];
	port = atoi(argv[2]);
	my_server_number = atoi(argv[3]);
	file_server_id = 1;
	
	if(argc == 6){
		file_server_pub_key = strdup(argv[4]);
		private_key = strdup(argv[5]);
	}
	else{
		file_server_pub_key = "./Certs/fileserver_public.pem";
		private_key = "./Certs/keyserver_privkey.pem";
	}
	
	printf("Setup\n\tip: %s\n\tport: %i\n\tserver number: %i\n", addr, port, my_server_number); 
	
	for(i = 0 ; i < N_ELEMENTS ; i++){
		secrets[i].secret = NULL;
	}
	next_elem = 0;
	
	//set up
	socketF = create_socket(addr, port);
	printf("Connessione al server %s (porta %i) effettuata con successo\n", addr, port);
	
	//hand shake iniziale
	/////////////////////////////////////////////////M1
	//send{ File_server, Key_server, noncep }Kf+
	noncep = generate_nonce(nonce_len);
	msg_len = sizeof(int) + sizeof(int) + nonce_len;
	msg = (unsigned char*)malloc(msg_len);
	memcpy(msg, &file_server_id, sizeof(int));
	memcpy(msg + sizeof(int), &my_server_number, sizeof(int));
	memcpy(msg + sizeof(int) + sizeof(int), noncep, nonce_len);
	printf("-------->M1: %i %i %i\n", (int)*msg, (int)*(msg+4), (int)*(msg+8));
	//encrypt
	enc_msg = asym_crypto(msg, msg_len, &enc_msg_len, file_server_pub_key);
	//send len
	send_msg(socketF, &enc_msg_len, sizeof(int));
	//send msg
	send_msg(socketF, enc_msg, enc_msg_len);
	//free
	free(msg);
	free(enc_msg);
	
	/////////////////////////////////////////////////M2
	//receive( {File_server, Key_server, noncep, nonces, K}kk+ )
	recv_msg(socketF, &enc_msg_len, sizeof(int));
	enc_msg = (unsigned char*)malloc(enc_msg_len);
	recv_msg(socketF, enc_msg, enc_msg_len);
	//decrypt
	msg = asym_decrypt(enc_msg, enc_msg_len, &msg_len, private_key);
	printf("-------->M2: %i %i %i %i\n", (int)*msg, (int)*(msg+4), (int)*(msg+8), (int)*(msg+12));
	if( (memcmp(msg, &file_server_id, sizeof(int)) != 0) || memcmp(msg + sizeof(int), &my_server_number, sizeof(int)) != 0 ){
		printf("Wrong server-id in the response\n");
		exit(-1);
	}
	if( memcmp(msg + sizeof(int) + sizeof(int), noncep, nonce_len) != 0 ){
		printf("Wrong nonce in the response\n");
		exit(-1);
	}
	//take nonces
	nonces = (unsigned char*)malloc(nonce_len);
	memcpy(nonces, msg + sizeof(int) + sizeof(int) + nonce_len, nonce_len);
	//take shared key
	shared_key = (unsigned char*)malloc(EVP_CIPHER_key_length(SYM_CIPHER));
	memcpy(shared_key, msg + sizeof(int) + sizeof(int) + nonce_len + nonce_len, EVP_CIPHER_key_length(SYM_CIPHER));
	//free
	free(enc_msg);
	free(msg);
	free(noncep);
	
	/////////////////////////////////////////////////M3
	//send( {nonces}K )
	printf("-------->M2: %i\n", (int)*(nonces));
	enc_msg = sym_crypt(nonces, nonce_len, shared_key, &enc_msg_len);
	//send len
	send_msg(socketF, &enc_msg_len, sizeof(int));
	//send msg
	send_msg(socketF, enc_msg, enc_msg_len);
	//free
	free(nonces);
	free(enc_msg);
	
	/////////////////////////////////////////////////loop
	while( 1 ){
		//ciclo di richieste del server
		printf("\n\n\n---> Waiting for request\n");
		
		//read command
		recv_msg(socketF, &enc_msg_len, sizeof(int));
		printf("enc_msg_len: %i\n", enc_msg_len);
		enc_msg = (unsigned char*)malloc(enc_msg_len);
		recv_msg(socketF, enc_msg, enc_msg_len);
		
		//decrypt command
		msg = (unsigned char*)sym_decrypt(enc_msg, enc_msg_len, shared_key, &msg_len);
		printf("msg_len: %i\n", msg_len);
		
		//le 3 righe sotto possono essere sostituite con un memcmp ?????????????
		/*uint8_t test;
		memcpy(&test, msg, msg_len);
		if(test == UPLOAD_KEY){*/
		if( memcmp(msg, &up_key, sizeof(uint8_t)) == 0 ){
			printf("\t\tUPLOAD COMMAND\n\n");
			
			//free
			free(enc_msg);
			free(msg);
			
			//read command <dim><Ek(hash(file)||x||dim_secret||secret||hash(payload))>
			recv_msg(socketF, &enc_msg_len, sizeof(int));
			enc_msg = (unsigned char*)malloc(enc_msg_len);
			recv_msg(socketF, enc_msg, enc_msg_len);
			
			//decrypt command
			msg = (unsigned char*)sym_decrypt(enc_msg, enc_msg_len, shared_key, &msg_len);
	
			//check integrity
			if(verify_hash(msg, msg_len - 32, NULL, msg + msg_len - 32) != 1){
				printf("corrupted\n");
				continue;
			}
			printf("Message not corrupted\n");
			
			//fill array field
			memcpy(secrets[next_elem].id, msg, 32);
			memcpy(&secrets[next_elem].x, msg + 32, sizeof(int));
			memcpy(&secrets[next_elem].dim_secret, msg + 32 + sizeof(int), sizeof(int));
			secrets[next_elem].secret = (unsigned char*)malloc(secrets[next_elem].dim_secret);
			memcpy(secrets[next_elem].secret, msg + 32 + sizeof(int) + sizeof(int), secrets[next_elem].dim_secret);
			
			print_secrets(secrets, N_ELEMENTS);
			
			printf("old head: %i\t", next_elem);
			do{
				next_elem = (next_elem + 1) % N_ELEMENTS;
			}while( secrets[next_elem].secret != NULL );
			printf("new head: %i\n", next_elem);
			
			//free
			free(enc_msg);
			free(msg);
			
			
		} else {
			if( memcmp(msg, &down_key, sizeof(uint8_t)) == 0 ){
				printf("\t\tDOWNLOAD COMMAND\n\n");
				
				//free
				free(enc_msg);
				free(msg);
				
				//read command <dim><Ek(file_id)>
				recv_msg(socketF, &enc_msg_len, sizeof(int));
				enc_msg = (unsigned char*)malloc(enc_msg_len);
				recv_msg(socketF, enc_msg, enc_msg_len);
				
				//decrypt command
				msg = (unsigned char*)sym_decrypt(enc_msg, enc_msg_len, shared_key, &msg_len);
				printf("-------->DOWNLOAD COMMAND: ");print_unsigned_char(msg, msg_len); printf("\n");
				
				//search for element
				i = 0;
				int stop = 0;
				//memcpy(hash, msg , 32);
				while( (i < N_ELEMENTS) && (stop == 0) ){
					printf("search index: %i\n", i);
					if(secrets[i].secret != NULL){
						if(memcmp(secrets[i].id, msg, 32) == 0){
							stop = 1;
							break;
						}
					}
					i++;
				}
				
				//free
				free(enc_msg);
				free(msg);
				
				printf("\n");
				
				if( i == N_ELEMENTS){
					printf("NOT FOUND\n");
					
					//send response
					uint8_t response = 3;
					msg_len = sizeof(uint8_t);
					msg = (unsigned char*)malloc(msg_len);
					memcpy(msg, &response, msg_len);
					
					enc_msg = sym_crypt(msg, msg_len, shared_key, &enc_msg_len);
					
					send_msg(socketF, &enc_msg_len, sizeof(int));
					send_msg(socketF, enc_msg, enc_msg_len);
					
					free(msg);
					free(enc_msg);
					
					continue;
				}
				print_secrets(secrets, N_ELEMENTS);
				printf("find at position: %i\n", i);
				
				
				
				//create response
				msg_len = 32 + sizeof(int) + sizeof(int) + secrets[i].dim_secret + 32;
				msg = (unsigned char*)malloc(msg_len);
				memcpy(msg, secrets[i].id, 32);
				memcpy(msg + 32, &secrets[i].x, sizeof(int));
				memcpy(msg + 32 + sizeof(int), &secrets[i].dim_secret, sizeof(int));
				memcpy(msg + 32 + sizeof(int) + sizeof(int), secrets[i].secret, secrets[i].dim_secret);
				hash = do_hash(msg, (msg_len - 32), NULL);
				memcpy(msg + 32 + sizeof(int) + sizeof(int) + secrets[i].dim_secret, hash, 32);
				/////////////////////////////controllare se per caso funziona al posto delle due righe sopra
				//(msg + 32 + sizeof(int) + sizeof(int) + secrets[i].dim_secret) = do_hash(msg, (msg_len - 32), NULL);
				
				//encrypt response
				enc_msg = sym_crypt(msg, msg_len, shared_key, &enc_msg_len);
				
				//send
				send_msg(socketF, &enc_msg_len, sizeof(int));
				send_msg(socketF, enc_msg, enc_msg_len);
				
				//free
				free(enc_msg);
				free(msg);
				
				//blank secret
				printf("blanking secret at position %i.\n", i);
				memset(secrets[i].secret, 0, secrets[i].dim_secret);
				free(secrets[i].secret);
				secrets[i].dim_secret = 0;
				secrets[i].secret = NULL;
				
				print_secrets(secrets, N_ELEMENTS);
				
			} else {
				printf("Unknow command\n");
				continue;
			}
		}
	}
	
	free(hash);
	
	return 0;
}
