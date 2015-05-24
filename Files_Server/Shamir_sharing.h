#include <openssl/bn.h>
#include <openssl/err.h>
#include <string.h>

struct secret_pieces{
	unsigned char* piece;
	int dim_piece;
	int x;
};

struct secret_pieces* secret_sharing(unsigned char* key, int key_size, int n_peers, int needed);
unsigned char* secret_recovery(struct secret_pieces* pieces, int n_pieces, int* outlen);
