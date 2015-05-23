#include "Shamir_sharing.h"

void print_bytes(unsigned char* buf, int len) {
  int i = 0;
  for (i = 0; i < len - 1; i++)
    printf("%02X:", buf[i]);
  printf("%02X", buf[len - 1]);
  printf("\n");
}


/*
* Given the array of coefficients it computes f(x) = secret + (C1 * x) + .... + (Ck-1 * x^k-1) 
* Returns the f(x), or NULL in case of errors
*/
BIGNUM* compute_function(int x, BIGNUM** coeff, int n_coeff, BIGNUM* secret){
	int i;
	int status;
	int temp;
	BN_CTX* ctx;
	BIGNUM* BN_i;
	BIGNUM* BN_x;
	BIGNUM* BN_pow;
	BIGNUM* ret;
	
	
	ret = BN_new();
	if(ret == NULL)
		return NULL;
	
	BN_pow = BN_new();
	if(BN_pow == NULL)
		goto error;
	
	BN_i = BN_new();
	if(BN_i == NULL)
		goto error;
	
	//Init. BIGNUM context
	ctx = BN_CTX_new();
	BN_CTX_init(ctx);
	
	BN_zero(ret);
	BN_zero(BN_pow);
	
	//Converts the integer in big-endian format
	temp = htonl(x);
	//Then converts it for doing BN math operation
	BN_x = BN_bin2bn((unsigned char*) &temp, sizeof(temp), NULL);
	if(BN_x == NULL)
		goto error;
		
	//Adds to return value the constant factor of f(x)
	status = BN_add(ret, secret, ret);
	if(status != 1)
		goto error;
	
	for(i = 1; i <= n_coeff; i++){
		temp = htonl(i);
		//Converts the index "i" for doing BN math operation
		BN_bin2bn((unsigned char*) &temp, sizeof(temp), BN_i);
		
		//Does the power of X
		status = BN_exp(BN_pow, BN_x, BN_i, ctx);
		if(status != 1)
			goto error;
		
		//Does the multiplication by the coefficient
		status = BN_mul(BN_pow, BN_pow, coeff[i-1], ctx);
		if(status != 1)
			goto error;
			
		//Adds the result to the global result 
		status = BN_add(ret, BN_pow, ret);
		if(status != 1)
			goto error; 
	}
	
	//Cleans the data structures
	//BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	BN_clear_free(BN_x);
	BN_clear_free(BN_pow);
	BN_clear_free(BN_i);
	
	return ret;
	
error:
	fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
	if(ret != NULL)
		BN_clear_free(ret);
	if(BN_x != NULL){
		BN_clear_free(BN_x);
	}
	if(BN_pow != NULL){
		BN_clear_free(BN_pow);
	}
	if(BN_i != NULL){
		BN_clear_free(BN_i);
	}
	if(ctx != NULL){
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
		
	return NULL;

}


/*
* Performs the "Shamir secret sharing" algorithm.
* Returns an "n_peers" array of secret pieces data structure.
* In case of error returns NULL.
*/
struct secret_pieces* secret_sharing(unsigned char* key, int key_size, int n_peers, int needed){
	BIGNUM* BN_key;
	BIGNUM* BN_temp;
	void* seed_buf;
	int dim;
	BIGNUM** coeff; 		//array of coefficients
	int i; 
	int ret;
	struct secret_pieces* results;
	
	//Checks
	if(key == NULL || key_size <= 0 || needed <= 0 || n_peers < needed){
		return NULL;
	}
	
	
	//Converts the key in a BIGNUM
	BN_key = BN_bin2bn(key, key_size, NULL);
	if(BN_key == NULL)
		return NULL;
	
	//Seed the RNG
	dim = 64;
	seed_buf = malloc(dim);
	RAND_seed(seed_buf, dim);
	
	//Generates the "needed" - 1 coefficients
	coeff = calloc(needed - 1, sizeof(BIGNUM * ));
	
	for(i = 0; i < needed - 1; i++){
		coeff[i] = BN_new();
		ret = BN_rand(coeff[i], key_size * 8, -1, 0);
		//Only positive integers are permitted, thus if it is negative sets it positive 
		if(BN_is_negative(coeff[i]))
			BN_set_negative(coeff[i], 0);
	}
	
	results = calloc(n_peers ,sizeof(struct secret_pieces));
	
	for(i = 1; i <= n_peers; i++){
		BN_temp = compute_function(i, coeff, needed - 1, BN_key);
		results[i-1].x = i;
		results[i-1].dim_piece = BN_num_bytes(BN_temp);
		results[i-1].piece = calloc(results[i-1].dim_piece, sizeof(char));
		BN_bn2bin(BN_temp, results[i-1].piece);
		
		BN_clear_free(BN_temp);
	}
	
	free(seed_buf);
	BN_clear_free(BN_key);
	free(coeff);
	return results;
}



int main(){		
	struct secret_pieces* prova = secret_sharing("password", 4, 5, 2);
	int i;
	int total = (sizeof(prova) / sizeof(struct secret_pieces));
	printf("Total: %i\n", total);
	
	for(i = 0; i < 5; i++){
		printf("Iteration %i:\t", i);
		printf("X = %i piece = ", prova[i].x);
		print_bytes(prova[i].piece, prova[i].dim_piece);
	}
}	
