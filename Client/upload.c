

int upload(SSL* connection, char* file_name, int dim_file_name){
	//symmetric cipher
	char* key;
	int key_len;
	EVP_CIPHER_CTX* ctx;
	
	//generate k
	key_len = EVP_CIPHER_key_length(SYM_CIPHER);
	key = (char*)malloc(key_len);
	RAND_seed(key, key_len);
	
	//send Ek(file || H(file))
	
	//send k
	
	//wait for response
	ret = secure_read(0, &server_response, sizeof(uint8_t), connection);
	check_ret(ret, sizeof(uint8_t));
	
}
