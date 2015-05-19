#include "utils.h"


unsigned char* do_hash(unsigned char* source, int source_size, char* name_file){
	int i;
	unsigned char data[1024];
	unsigned int digest_size = EVP_MD_size(EVP_sha256());	
	unsigned char* hash = malloc(digest_size);
	int read_bytes;
	FILE* input_file;
	
	if(source == NULL || source_size <= 0)
	
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

/*
* Computes the hash function SHA256 on "source" buffer, AND on the content of file "name_file" if it is non-NULL
* then compares it with the content of "hash_val" buffer
* Returns 1 if the integrity is verified, 0 otherwise, -1 in case of errors
*/
int verify_hash(unsigned char* source, int source_size, char* name_file ,unsigned char* hash_val){
	unsigned char* computed_hash;
	int ret;
	
	/*Checks*/
	if(source == NULL || hash_val == NULL || source_size <= 0)
		return -1;
		
	/*Computes the hash function on source buffer and on file (if needed)*/
	computed_hash = do_hash(source, source_size, name_file);
	
	/*Checks if they are equals*/
	ret = CRYPTO_memcmp(computed_hash, hash_val, EVP_MD_size(EVP_sha256()));
	
	free(computed_hash);
	
	if(ret == 0)
		return 1;
	else
		return 0;
}
