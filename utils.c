unsigned char* do_hash(unsigned char* source, int source_size, char* name_file){
	int i;
	unsigned char data[1024];
	unsigned int digest_size = 32;			//penso che ci sia una costante nella libreria ma non la trovo
	unsigned char hash[digest_size];
	int read_bytes;
	FILE* input_file;
	
	EVP_MD_CTX sha_ctx;
	EVP_MD_CTX_init(&sha_ctx);
	
	EVP_DigestInit(&sha_ctx, EVP_sha256());
	
	EVP_DigestUpdate(&sha_ctx, source, source_size);
	
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
	
	EVP_DigestFinal(&sha_ctx, hash, &digest_size);
	
	EVP_MD_CTX_cleanup(&sha_ctx);
	
	printf("sha256 of the passed data is: \n");
	for(i = 0 ; i <= digest_size ; i++)
		printf("%02x", hash[i]);
	printf("\n");
	
	return hash;
}