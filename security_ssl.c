#include "security_ssl.h"

//If password is needed to load the private key of the server, it asks to the user
int pem_passwd_cb(char *buf, int size, int rwflag, void *password){
 	int ret;
 	printf("Enter your password for private key: ");
	ret = scanf("%s", buf);
 	//**********************************************************************************************vulnerabilità di segmentation fault, input > buffer size
	buf[size - 1] = '\0';
	return(strlen(buf));
 }
 

//funzione che crea il contesto, i parametri all'inizio potranno essere pochi ed elementari, più avanti si darà la possibilità
//di creare una sessione ssl passandogli i certificati da usare, password, etc etc
SSL_CTX* create_SSL_context(const char* cert_file, const char* prvkey_file){
	SSL_CTX* ctx;
	int error;
	int i;
	
	SSL_library_init();
	
	SSL_load_error_strings();
	
	ctx = SSL_CTX_new(SSLv23_method());

    	if (ctx == NULL) {
        	fprintf(stderr, "Can't initialize SSL_CTX\n");
        	return NULL;
    	}
    	//abilito write parziali (cioè scrivono meno byte di quelli specificati) e il release dei buffer nelle connessioni ssl idle, per risparmiare ram
    	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS); 	//SSL_MODE_ENABLE_PARTIAL_WRITE rimosso per ora
    	
    	SSL_CTX_set_cipher_list(ctx, SSL_CIPHERS);
    	
    	error = SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
    	if(error != 1){
    		fprintf(stderr, "Can't load public certificate: %s\n", ERR_error_string(ERR_get_error(), NULL));
        	return NULL;
    	}
    	
    	printf("OPENSSL: Server certificate file loaded\n");
    	
    	SSL_CTX_set_default_passwd_cb(ctx,pem_passwd_cb);
    	
    	error = SSL_CTX_use_PrivateKey_file(ctx, prvkey_file, SSL_FILETYPE_PEM);
    	if(error != 1){
    		fprintf(stderr, "Can't load private key, wrong password maybe?\n");
        	return NULL;
    	}
    	
    	printf("OPENSSL: Server private key file loaded\n");
    	
    	error = SSL_CTX_check_private_key(ctx);
    	if(error != 1){
    		fprintf(stderr, "Private key does not match the public certificate.\n");
        	return NULL;
    	}
    	//non è richiesta l'autenticazione del client (visto che agiremo sul web)
    	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); 
    	
    	return ctx;
}
//funzione che associa un socket al SSL_socket
SSL* bind_socket_to_SSL(SSL_CTX* ctx, int sock){
	SSL* ssl_sock;
	int error;
	if(ctx == NULL || sock < 0){
		fprintf(stderr, "Error during the SSL socket bind: invalid arguments\n");
        	return NULL;
	}
	
	ssl_sock = SSL_new(ctx);
	if(ssl_sock == NULL){
		fprintf(stderr, "Error during the SSL socket creation\n");
        	return NULL;
	}
	
	error = SSL_set_fd(ssl_sock, sock);
	if(error != 1){
		fprintf(stderr, "Error during the SSL socket creation\n");
        	return NULL;	
	}
	
	return ssl_sock;
}

//funzione che accetta nuove connessioni dal client
int server_accept(SSL* ssl_sock){
	int error;
	error = SSL_accept(ssl_sock);
	if(error != 1){
		fprintf(stderr, "Error during the SSL handshake: %s\n", ERR_error_string(ERR_get_error(), NULL));
		SSL_free(ssl_sock);
        	return -1;
	}
	
	return 1;
}

//funzione che connette il client al server
int client_connect(SSL* ssl_sock){
	int error;
	error = SSL_connect(ssl_sock);
	if(error != 1){
		fprintf(stderr, "Error during the SSL handshake: %s\n", ERR_error_string(ERR_get_error(), NULL));
		SSL_free(ssl_sock);
        	return -1;
	}
	
	return 1;
}

//funzione di read sulla sessione ssl 
int secure_read(int fd, void* buffer, int count, SSL* sock){
	int ret;
	//printf("secure_read\n");
	if(sock == NULL)
		return read(fd, buffer, count);
	else{
		ret = SSL_read(sock, buffer, count);
		//printf("ret = %i content =\n%s", ret, buffer);
		return ret;
	}
}

//funzione di write sulla sessione ssl 
int secure_write(int fd, void* buffer, int count, SSL* sock){
	//printf("secure_write\n");
	if(sock == NULL)
		return write(fd, buffer, count);
	else
		return SSL_write(sock, buffer, count);
}

//funzione di cleanup del contesto
void ssl_context_cleanup(SSL_CTX* ctx){
	SSL_CTX_free(ctx);
    return;
}

