#include "utils.h"


void print_bytes(unsigned char* buf, int len) {
  int i = 0;
  for (i = 0; i < len - 1; i++)
    printf("%02X:", buf[i]);
  printf("%02X", buf[len - 1]);
  printf("\n");
}

int main(){
	unsigned char* hash_val;
	unsigned char* buf = "stringa di prova";
	char* name_file = "./VIDEO0015.mp4";
	int ret;
	
	hash_val = do_hash(buf, strlen(buf), name_file);
	
	printf("Hash Value = \n");
	print_bytes(hash_val, EVP_MD_size(EVP_sha256()));
	
	ret = verify_hash(buf, strlen(buf), name_file, hash_val);
	if(ret == 1)
		printf("Integrity verified\n");
	else
		printf("Integrity check failed\n");
	
	return 0;	
}
