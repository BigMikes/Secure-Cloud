#include "../utils.h"

void print_bytes(unsigned char* buf, int len) {
  int i = 0;
  for (i = 0; i < len - 1; i++)
    printf("%02X:", buf[i]);
  printf("%02X", buf[len - 1]);
  printf("\n");
}


int main(){
	unsigned char* plaintext = "Prova RSA\0";
	unsigned char* ciphertext;
	int cipher_dim;
	unsigned char* plaintext2;
	
	ciphertext = asym_crypto(plaintext, strlen(plaintext), &cipher_dim, "rsa_pubkey.pem");
	
	printf("Ciphertext dim = %i\n", cipher_dim);
	print_bytes(ciphertext, cipher_dim);
	
	plaintext2 = asym_decrypt(ciphertext, cipher_dim, &cipher_dim, "rsa_privkey.pem");
	
	printf("Dim = %i Plaintext = %s\n", cipher_dim, plaintext2);
	return 0;
}
