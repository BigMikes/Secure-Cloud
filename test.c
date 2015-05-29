#include "utils.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/rand.h>

void print_bytes(unsigned char* buf, int len) {
  int i = 0;
  for (i = 0; i < len - 1; i++)
    printf("%02X:", buf[i]);
  printf("%02X", buf[len - 1]);
  printf("\n");
}

int main(){
	
	unsigned char* hash_val;
	char* name_file = "utils.c";
	int ret;
	unsigned char* cipher;
	int cipher_len;
	
	//chiavi
	//symmetric cipher
		unsigned char* key;
		int key_len;
		
		//generate k
		key_len = EVP_CIPHER_key_length(SYM_CIPHER);
		key = (unsigned char*)malloc(key_len);
		RAND_seed(key, key_len);
		RAND_bytes(key, key_len);
	////
	
	hash_val = do_hash(NULL, 0, name_file);
	
	printf("Hash Value = \n");
	print_bytes(hash_val, EVP_MD_size(EVP_sha256()));
	
	ret = verify_hash(NULL, 0, name_file, hash_val);
	if(ret == 1)
		printf("Integrity verified\n\n");
	else
		printf("Integrity check failed\n\n");
	
	//file encrypt
	cipher = sym_crypto_file(name_file, hash_val, EVP_MD_size(EVP_sha256()), key, &cipher_len);
	
	struct stat st;
	stat(name_file, &st); //file_size = st.st_size;
	printf("test_file long: %i\n", (int)st.st_size);
	printf("test_cipher_len: %i\n\n\n", cipher_len);
	
	//string encrypt
	char* a = "ciao come va";
	int l = strlen(a);
	printf("stringa: %s\t\t lunga: %i\n", a, l);
	cipher = sym_crypt(a, l, key, &cipher_len);
	
	printf("cipher: %s\t\t lungo: %i\n\n", cipher, cipher_len);
	
	//string decrypt
	int plain_len;
	char* plain = sym_decrypt(cipher, cipher_len, key, &plain_len);
	printf("plain text: %s\t\t lungo: %i\n", plain, plain_len);
	
	return 0;	
}
