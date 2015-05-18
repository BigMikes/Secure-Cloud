#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

unsigned char* do_hash(unsigned char* source, int source_size, char* name_file);
int verify_hash(unsigned char* source, int source_size, char* name_file ,unsigned char* hash_val);

