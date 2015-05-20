#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define SYM_CIPHER EVP_aes_256_cbc()

unsigned char* do_hash(unsigned char* source, int source_size, char* name_file);
int verify_hash(unsigned char* source, int source_size, char* name_file ,unsigned char* hash_val);
unsigned char* sym_crypto(unsigned char* source, int source_size, char* name_file, unsigned char* key);

