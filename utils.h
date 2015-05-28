#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SYM_CIPHER EVP_aes_256_cbc()

unsigned char* do_hash(unsigned char* source, int source_size, char* name_file);

int verify_hash(unsigned char* source, int source_size, char* name_file ,unsigned char* hash_val);

unsigned char* sym_crypto(unsigned char* source, int source_size, char* name_file, unsigned char* key);

unsigned char* asym_crypto(unsigned char* plaintext, int in_len, int* out_len, char* pub_key_file);

unsigned char* asym_decrypt(unsigned char* ciphertext, int in_len, int* out_len, char* priv_key_file);

