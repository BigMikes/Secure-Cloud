#include <openssl/bn.h>
#include <openssl/err.h>

struct secret_pieces{
	unsigned char* piece;
	int dim_piece;
	int x;
};

struct secret_pieces* secret_sharing(unsigned char* key, int key_size, int n_peers, int needed);
