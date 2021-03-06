#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#define SYM_CIPHER EVP_aes_256_cbc()
#define HASH_FUN EVP_sha256()

unsigned char* do_hash(unsigned char* source, int source_size, char* name_file);

int verify_hash(unsigned char* source, int source_size, char* name_file ,unsigned char* hash_val);

unsigned char* sym_crypto_file(char* name_file, unsigned char* hash, int hash_size, unsigned char* key, int* cipher_len);

unsigned char* sym_crypt(void* buf, int buf_size, unsigned char* key, int* cipher_len);

char* sym_decrypt(unsigned char* cipher, int cipher_len, unsigned char* key, int* output_len);

unsigned char* asym_crypto(unsigned char* plaintext, int in_len, int* out_len, char* pub_key_file);

unsigned char* asym_decrypt(unsigned char* ciphertext, int in_len, int* out_len, char* priv_key_file);

