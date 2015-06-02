#include "utils.h"

/*
* Computes the hash function SHA256 on "source" buffer, AND on the content of file "name_file" if it is non-NULL
* Returns the hash value, NULL in case of errors
*/
unsigned char* do_hash(unsigned char* source, int source_size, char* name_file){
	int i;
	unsigned char data[1024];
	unsigned int digest_size = EVP_MD_size(HASH_FUN);	
	unsigned char* hash = malloc(digest_size);
	int read_bytes;
	FILE* input_file;
	EVP_MD_CTX sha_ctx;
	
	if( (source == NULL && name_file == NULL) || (source != NULL && source_size <= 0) ){
		return NULL;
	}
	
	EVP_MD_CTX_init(&sha_ctx);
	
	EVP_DigestInit(&sha_ctx, HASH_FUN);
	
	//update sul file
	if(name_file != NULL){
		input_file = fopen(name_file, "r");
		if(input_file==NULL){
			printf("Impossible to open file.\n");
			return NULL;
		}
		
		while( ( read_bytes = fread(data, 1, 1024, input_file) ) != 0 ){
			EVP_DigestUpdate(&sha_ctx, data, read_bytes);
		}
		
		fclose(input_file);
	}
	
	//update sul buffer
	if(source != NULL){
		EVP_DigestUpdate(&sha_ctx, source, source_size);
	}
	
	EVP_DigestFinal(&sha_ctx, hash, &digest_size);
	
	EVP_MD_CTX_cleanup(&sha_ctx);
	
	printf("sha256 of the passed data is: \n");
	for(i = 0 ; i < digest_size ; i++)
		printf("%02x", hash[i]);
	printf("\n");
	
	return hash;
}

/*
* Computes the hash function SHA256 on "source" buffer, AND on the content of file "name_file" if it is non-NULL
* then compares it with the content of "hash_val" buffer
* Returns 1 if the integrity is verified, 0 otherwise, -1 in case of errors
*/
int verify_hash(unsigned char* source, int source_size, char* name_file ,unsigned char* hash_val){
	unsigned char* computed_hash;
	int ret;
	
	/*Checks*/
	if( (source == NULL && name_file == NULL) || (source != NULL && name_file != NULL) || (source != NULL && name_file == NULL && source_size <= 0) ){
		return -1;
	}
		
	/*Computes the hash function on source buffer and on file (if needed)*/
	if(name_file != NULL){
		computed_hash = do_hash(NULL, 0, name_file);
	}
	
	if(source != NULL){
		computed_hash = do_hash(source, source_size, NULL);
	}
	//penso che basti anche semplicente fare 
	//computed_hash = do_hash(source, source_size, name_file);
	//senza bisogno degli if
	
	/*Checks if they are equals*/
	ret = CRYPTO_memcmp(computed_hash, hash_val, EVP_MD_size(HASH_FUN));
	
	free(computed_hash);
	
	if(ret == 0)
		return 1;
	else
		return 0;
}

/*
* Crypting function AES256-CBC on "source" buffer (if non-NULL), AND on the content of file "name_file" (if non-NULL)
* It is an error if "source" and "name_file" are both equal to NULL.
* Returns the ciphertext, NULL in case of errors
*/
unsigned char* sym_crypto_file(char* name_file, unsigned char* hash, int hash_size, unsigned char* key, int* cipher_len){
	EVP_CIPHER_CTX* ctx;
	FILE* fd;
	unsigned char* ciphertext;
	unsigned char* plaintext;
	int res, msg_len, n;
	int outlen, outlen_tot;
	int ct_bufsize;
	struct stat st;
	int block_size = EVP_CIPHER_block_size(SYM_CIPHER);
	
	//printf("block_size: %i\n", block_size);
	
	if(hash == NULL || name_file == NULL || key == NULL)
		return NULL;
	
	fd = fopen(name_file, "r");
	if(fd == NULL){
		printf("Impossible to open %s file\n", name_file);
		return NULL;
	}
	
	stat(name_file, &st); //file_size = st.st_size;
	plaintext = (unsigned char*)malloc(st.st_size+hash_size);		//plaintext grande come il file più hash
	
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));	
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx, SYM_CIPHER, key, NULL);		//Cosa fare con l' IV?
	
	//plaintext allocation
	res=fread(plaintext, sizeof(char), st.st_size, fd); // in res ci sono i byte letti
	if(res != st.st_size){
		printf("reading error");
		return NULL;
	}
	
	//append hash
	memcpy(plaintext + st.st_size, hash, hash_size);
	
	/* Buffer allocation for the ciphertext */
	msg_len = st.st_size+hash_size;
	ct_bufsize = msg_len + block_size;
	ciphertext = (unsigned char*)malloc(ct_bufsize);
	
	
	
	outlen = 0;
	outlen_tot = 0;//dimensione testo output(ciphertext)
	n=0;//dimensione testo input (plaintext)
	while(n/block_size < msg_len/block_size){//block size serve nel caso in cui msg_len < block_size allora non devo entrare nel ciclo
		EVP_EncryptUpdate(ctx, ciphertext + outlen_tot, &outlen, (unsigned char*)plaintext + n,block_size);
		outlen_tot += outlen;
		n += block_size;
	}
	EVP_EncryptUpdate(ctx, ciphertext + outlen_tot, &outlen, (unsigned char*)plaintext + n,msg_len % block_size);// cifro i byte restanti(quelli non multipli di block size
	outlen_tot += outlen;
	n += msg_len % block_size;
	EVP_EncryptFinal(ctx, ciphertext + outlen_tot, &outlen);
	outlen_tot += outlen;
	
	EVP_CIPHER_CTX_cleanup(ctx);
	
	free(ctx);
	
	*cipher_len = outlen_tot;
	printf("ciphertext long: %i\n", outlen_tot);
	return ciphertext;
}

/*
 * 
 */
unsigned char* sym_crypt(void* buf, int buf_size, unsigned char* key, int* cipher_len){
	EVP_CIPHER_CTX* ctx;
	FILE* fd;
	unsigned char* ciphertext;
	int res, msg_len, n;
	int outlen, outlen_tot;
	int ct_bufsize;
	int block_size = EVP_CIPHER_block_size(SYM_CIPHER);
	
	//printf("block_size: %i\n", block_size);
	
	if(buf == NULL || key == NULL)
		return NULL;
	
	
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));	
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx, SYM_CIPHER, key, NULL);		//Cosa fare con l' IV?
	
	
	/* Buffer allocation for the ciphertext */
	msg_len = buf_size;
	ct_bufsize = msg_len + block_size;
	ciphertext = (unsigned char*)malloc(ct_bufsize);
	
	
	
	outlen = 0;
	outlen_tot = 0;//dimensione testo output(ciphertext)
	n=0;//dimensione testo input (plaintext)
	while(n/block_size < msg_len/block_size){//block size serve nel caso in cui msg_len < block_size allora non devo entrare nel ciclo
		EVP_EncryptUpdate(ctx, ciphertext + outlen_tot, &outlen, (unsigned char*)buf + n,block_size);
		outlen_tot += outlen;
		n += block_size;
	}
	EVP_EncryptUpdate(ctx, ciphertext + outlen_tot, &outlen, (unsigned char*)buf + n,msg_len % block_size);// cifro i byte restanti(quelli non multipli di block size
	outlen_tot += outlen;
	n += msg_len % block_size;
	EVP_EncryptFinal(ctx, ciphertext + outlen_tot, &outlen);
	outlen_tot += outlen;
	
	EVP_CIPHER_CTX_cleanup(ctx);
	
	free(ctx);
	
	*cipher_len = outlen_tot;
	return ciphertext;
}


/*
 * NB: questa funzione restituisce un buffer più grande del dovuto per cui 
 * fare sempre riferimento al valore di output_len
 */
char* sym_decrypt(unsigned char* cipher, int cipher_len, unsigned char* key, int* output_len){
	char* plaintext;
	int outlen, outlen_tot, n, len, res;
	int block_size = EVP_CIPHER_block_size(SYM_CIPHER);
	
	if(cipher == NULL || key == NULL){
		return NULL;
	}
	
	plaintext = (char*)malloc(cipher_len + block_size);
	
	EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	EVP_DecryptInit(ctx, SYM_CIPHER, key, NULL);
	
	len = cipher_len;	//passaggio inutile ma serve per mantenere una continuità con le funzioni precedenti
	/* Decryption */
	outlen = 0;
	outlen_tot = 0;// dim testo output (plaintext)
	n=0;//dim testo input (ciphertext)
	while(n/block_size < len/block_size){
		EVP_DecryptUpdate(ctx, plaintext+ outlen_tot, &outlen, (char*)cipher+ n, block_size);
		outlen_tot += outlen;
		n += block_size;
	}
	EVP_DecryptUpdate(ctx, plaintext+ outlen_tot, &outlen, (char*)cipher+ n, len % block_size);
	outlen_tot += outlen;
	n += len % block_size;
	res = EVP_DecryptFinal(ctx, plaintext + outlen_tot, &outlen);
	if(res == 0){
		printf("ERROR in decrypting.\n");
		return NULL;
	}
	outlen_tot += outlen;
	
	
	EVP_CIPHER_CTX_cleanup(ctx);
	
	*output_len = outlen_tot;
	return plaintext;
	
}



EVP_PKEY* retrieve_pubkey(const char* file_name) {
	FILE* file;
	EVP_PKEY* pubkey;
	file = fopen(file_name, "r");
	if(file == NULL){
		fprintf(stderr, "Error: cannot read PEM file '%s'\n", file_name);
	        return NULL;
	}

	pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	fclose(file);
	if(pubkey == NULL){
		fprintf(stderr, "Error: PEM_read_PUBKEY returned NULL\n");
		return NULL;
	}

	return pubkey;
}

/*
* RSA public cryptography function.
* Encrypt 'in_len' bytes from 'plaintext' buffer with the public key contained in 'pub_key_file' 
* Parameter 'outlen' is the size of output buffer 
* It returns the envelope which has to be sent to the receiver or NULL if an error occurs.
*/
unsigned char* asym_crypto(unsigned char* plaintext, int in_len, int* out_len, char* pub_key_file){
	EVP_PKEY* pubkey;
	int ret;	
	EVP_CIPHER_CTX* ctx;
	unsigned char* encrypted_key;
	int encrypted_key_len;
	unsigned char* iv;
	int iv_len;
	unsigned char* ciphertext;
	int cipher_len;
	int app;
	unsigned char* output;
	int total_output_size = 0;
		
	if(plaintext == NULL || in_len < 0 || out_len == NULL || pub_key_file == NULL)
		return NULL;
	
	//Reads the receiver's public key for its file
	pubkey = retrieve_pubkey(pub_key_file);
	if(pubkey == NULL)
		return NULL;
	encrypted_key_len = EVP_PKEY_size(pubkey);
	total_output_size += encrypted_key_len;
	iv_len = EVP_CIPHER_iv_length(SYM_CIPHER);
	total_output_size += iv_len;
	//Allocation of encrypted symmetric key and initialization vector
   	encrypted_key = malloc(encrypted_key_len);
   	iv = malloc(iv_len);
	//Seeding the RNG
	RAND_seed(iv, 8);
	
	//Instantiate and initialize the context
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_SealInit(ctx, SYM_CIPHER, &encrypted_key, &encrypted_key_len, iv, &pubkey ,1);
	if(ret == 0){
		fprintf(stderr, "Error in SealInit\n");
		goto error;
	}
	
	//Encrypt the input buffer
	cipher_len = in_len + EVP_CIPHER_block_size(SYM_CIPHER);
	ciphertext = malloc(cipher_len);
	cipher_len = 0;
	
	ret = EVP_SealUpdate(ctx, ciphertext, &app, plaintext, in_len);
	cipher_len += app;
	if(ret == 0){
		fprintf(stderr, "Error in SealUpdate\n");
		goto error;
	}
	ret = EVP_SealFinal(ctx, ciphertext + app, &app);
	cipher_len += app;
	if(ret == 0){
		fprintf(stderr, "Error in SealFinal\n");
		goto error;
	}
	total_output_size += cipher_len;
	
	//Concatenates the envelop in the outbuffer with format: <IV><Dim_Key><Ecrypt_KEY><Ciphertext>
	total_output_size += sizeof(int);
	output = malloc(total_output_size);
	app = 0;
	//<IV>
	memcpy(output, iv, iv_len);
	app += iv_len;
	//<Dim_Key>
	memcpy(output + app, &encrypted_key_len, sizeof(int));
	app += sizeof(int);
	//<Ecrypt_KEY>
	memcpy(output + app, encrypted_key, encrypted_key_len);
	app += encrypted_key_len;
	//<Ciphertext>
	memcpy(output + app, ciphertext, cipher_len);
	app += encrypted_key_len;
	
	*out_len = total_output_size;
	
	//Cleanup
	EVP_CIPHER_CTX_cleanup(ctx);
   	free(ctx);
	free(ciphertext);
	free(pubkey);
	free(iv);
	
	return output;
	
error:
	if(ctx != NULL){
		EVP_CIPHER_CTX_cleanup(ctx);
   		free(ctx);
	}
	if(encrypted_key != NULL)
		free(ciphertext);	
	if(pubkey != NULL)
		free(pubkey);
	if(iv != NULL)		
		free(iv);
	if(ciphertext != NULL)
		free(ciphertext);		
	if(output != NULL)
		free(output);
	return NULL;
}


EVP_PKEY* read_priv_key(const char* file_name){
	FILE* fp;
	EVP_PKEY* priv_key;
	
	fp = fopen(file_name, "r");
	if(fp == NULL){
		fprintf(stderr, "Error: cannot read PEM file '%s'\n", file_name);
	        return NULL;
	}
	priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if(priv_key == NULL){
		fprintf(stderr, "Error: PEM_read_PrivateKey returned NULL\n");
		return NULL;
	}
	
	return priv_key;
}

/*
* RSA public decryption function.
* Dencrypt 'in_len' bytes from 'envelope' buffer with the private key contained in 'priv_key_file' 
* Parameter 'outlen' is the size of output buffer 
* It returns the received plaintext or NULL if an error occurs.
*/
unsigned char* asym_decrypt(unsigned char* envelope, int in_len, int* out_len, char* priv_key_file){
	EVP_PKEY* priv_key;
	int ret;	
	EVP_CIPHER_CTX* ctx;
	unsigned char* encrypted_key;
	int encrypted_key_len;
	unsigned char* iv;
	int iv_len;
	unsigned char* ciphertext;
	int ciphertext_len;
	unsigned char* output;
	int output_len;
	int app;
	
		
	if(ciphertext == NULL || in_len < 0 || out_len == NULL || priv_key_file == NULL)
		return NULL;
	
	//Reads the receiver's public key for its file
	priv_key = read_priv_key(priv_key_file);
	
	//Note: envelope format -> <IV><Dim_Key><Ecrypt_KEY><Ciphertext>
	
	//Set to the head the iv pointer
	iv = envelope;
	iv_len = EVP_CIPHER_iv_length(SYM_CIPHER);
	
	//Read from the envelop the encrypted_key_len
	memcpy(&encrypted_key_len, envelope + iv_len, sizeof(int));
	
	//Set the encrypted_key pointer
	encrypted_key = envelope + iv_len + sizeof(int);
	
	//Set the ciphertext pointer
	ciphertext = envelope + iv_len + sizeof(int) + encrypted_key_len;
	ciphertext_len = in_len - iv_len - sizeof(int) - encrypted_key_len;
	
	//Instantiate and initialize the context
	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	ret = EVP_OpenInit(ctx, SYM_CIPHER, encrypted_key, encrypted_key_len, iv, priv_key);
	if(ret == 0)
		goto error;
	
	//Decrypt the ciphertext
	output_len = ciphertext_len;
	output = malloc(output_len);
	output_len = 0;
	ret = EVP_OpenUpdate(ctx, output, &app, ciphertext, ciphertext_len);
	if(ret == 0)
		goto error;
		
	output_len += app;
	ret = EVP_OpenFinal(ctx, output + app, &app);
	if(ret == 0)
		goto error;
	output_len += app;
	
	*out_len = output_len;
	
	//Cleanup	
	EVP_CIPHER_CTX_cleanup(ctx);
   	free(ctx);
	free(priv_key);
	
	return output;
error:
	if(ctx != NULL){
		EVP_CIPHER_CTX_cleanup(ctx);
   		free(ctx);
	}
	if(encrypted_key != NULL)
		free(ciphertext);	
	if(priv_key != NULL)
		free(priv_key);
	if(iv != NULL)		
		free(iv);
	if(ciphertext != NULL)
		free(ciphertext);		
	if(output != NULL)
		free(output);
	return NULL;
	
}

