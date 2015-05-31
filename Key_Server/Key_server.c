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
		exit(-1);
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

unsigned char* generate_nonce(int len){
	unsigned char* nonce = (unsigned char*)malloc(len);
	int ret = RAND_bytes(nonce, len);
	if(ret == 0){
		printf("error in nonce generation");
		exit(-1);
	}
	return nonce;
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
		file_server_pub_key = "./Certs/fileserver_pubkey.pem";
		private_key = "./Certs/keyserver_privkey.pem";
	}
	
	
	printf("Setup\n\tip: %s\n\tport: %i\n\tserver number: %i\n", addr, port, my_server_number); 
	
	//set up
	socketF = create_socket(addr, port);
	printf("Connessione al server %s (porta %i) effettuata con successo\n", addr, port);
	
	
	//hand shake iniziale
	//send{ File_server, Key_server, noncep }Kf+
	noncep = generate_nonce(nonce_len);
	msg_len = sizeof(int) + sizeof(int) + nonce_len;
	msg = (unsigned char*)malloc(msg_len);
	memcpy(msg, &file_server_id, sizeof(int));
	memcpy(msg + sizeof(int), &my_server_number, sizeof(int));
	memcpy(msg + sizeof(int) + sizeof(int), noncep, nonce_len);
	printf("M1: %.*s\n", msg_len, msg);
	//encrypt
	enc_msg = asym_crypto(msg, msg_len, &enc_msg_len, file_server_pub_key);
	//send len
	printf("\t\tsend len msg 1\n");
	send_msg(socketF, &enc_msg_len, sizeof(int));
	//send msg
	printf("\t\tsend msg 1\n");
	send_msg(socketF, enc_msg, enc_msg_len);
	//free
	free(msg);
	free(enc_msg);
	//-------------------------
	
	//receive( {File_server, Key_server, noncep, nonces, K}kk+ )
	printf("\t\treceive msg 2 len\n");
	recv_msg(socketF, &enc_msg_len, sizeof(int));
	enc_msg = (unsigned char*)malloc(enc_msg_len);
	printf("\t\treceive msg 2\n");
	recv_msg(socketF, enc_msg, enc_msg_len);
	//decrypt
	msg = asym_decrypt(enc_msg, enc_msg_len, &msg_len, private_key);
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
	//---------------------
	
	//send( {nonces}K )
	enc_msg = sym_crypt(nonces, nonce_len, shared_key, &enc_msg_len);
	//send len
	printf("\t\tsend len msg 3\n");
	send_msg(socketF, &enc_msg_len, sizeof(int));
	//send msg
	printf("\t\tsend msg 3\n");
	send_msg(socketF, enc_msg, enc_msg_len);
	
	
	while( 1 ){
		//ciclo di richieste del server
		//la richiesta può essere di storage o di retrieve
	}
	
	return 0;
}
