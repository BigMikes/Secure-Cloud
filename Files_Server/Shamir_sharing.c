#include "Shamir_sharing.h"


#define DIM_KEY 256


void print_bytes(unsigned char* buf, int len) {
  int i = 0;
  for (i = 0; i < len - 1; i++)
    printf("%02X:", buf[i]);
  printf("%02X", buf[len - 1]);
  printf("\n");
}


/*
* Function that convert an integer to a BIGNUM
*/
BIGNUM* int2BN(int x, BIGNUM* ret){
	int temp;
	temp = htonl(x);
	
	if(ret == NULL)
		return BN_bin2bn((unsigned char*) &temp, sizeof(temp), NULL);
	else
		BN_bin2bn((unsigned char*) &temp, sizeof(temp), ret);
	return NULL;
	
}

void get_max_value(BIGNUM* bn, int n){
	BIGNUM* one = int2BN(1, NULL);
	BN_set_bit(bn, n);
	BN_set_negative(one, 1);
	BN_add(bn, bn, one);
}

/*
* Given the array of coefficients it computes f(x) = secret + (C1 * x) + .... + (Ck-1 * x^k-1) 
* Returns the f(x), or NULL in case of errors
*/
BIGNUM* compute_function(int x, BIGNUM** coeff, int n_coeff, BIGNUM* secret){
	int i;
	int status;
	BN_CTX* ctx;
	BIGNUM* BN_i;
	BIGNUM* BN_x;
	BIGNUM* BN_pow;
	BIGNUM* ret;
	BIGNUM* modulus;
	
	
	ret = BN_new();
	if(ret == NULL)
		return NULL;
	
	BN_pow = BN_new();
	if(BN_pow == NULL)
		goto error;
	
	BN_i = BN_new();
	if(BN_i == NULL)
		goto error;
	modulus = BN_new();
	if(modulus == NULL)
		goto error;
	
	get_max_value(modulus, DIM_KEY);
	
	//Init. BIGNUM context
	ctx = BN_CTX_new();
	BN_CTX_init(ctx);
	
	BN_zero(ret);
	BN_zero(BN_pow);
	
	
	//Then converts it for doing BN math operation
	BN_x = int2BN(x, NULL);
	if(BN_x == NULL)
		goto error;
		
	//Adds to return value the constant factor of f(x)
	status = BN_add(ret, secret, ret);
	if(status != 1)
		goto error;
	
	for(i = 1; i <= n_coeff; i++){
		//Converts the index "i" for doing BN math operation
		int2BN(i, BN_i);
		
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
	BN_CTX_free(ctx);
	BN_clear_free(BN_x);
	BN_clear_free(BN_pow);
	BN_clear_free(BN_i);
	BN_clear_free(modulus);
	
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
	if(modulus != NULL){
		BN_clear_free(modulus);
	}
	if(ctx != NULL){
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
	
	/*-----DEBUG-----
	printf("Key = ");
	BN_print_fp(stdout, BN_key);
	printf("\n");
	*/
	
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
		
		/*-----DEBUG-----
		printf("Coeff %i = ", i + 1);
		BN_print_fp(stdout, coeff[i]);
		printf("\n");*/
	}
	
	results = calloc(n_peers ,sizeof(struct secret_pieces));
	
	for(i = 1; i <= n_peers; i++){
		BN_temp = compute_function(i, coeff, needed - 1, BN_key);
		
		/*-----DEBUG-----
		printf("Results = ");
		BN_print_fp(stdout, BN_temp);
		printf("\n");*/
		
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



/*
* Given the N pieces of secret (x, f(x)) computes the point x0 of function (that is the original secret)
* The dimention of the output buffer is *outlen 
*/
unsigned char* secret_recovery(struct secret_pieces* pieces, int n_pieces, int* outlen){
	BIGNUM* secret;
	BIGNUM* temp;
	BIGNUM* BN_x_j;
	BIGNUM* BN_x_i;
	BIGNUM* rem;
	BIGNUM* modulus;
	int i = 0;
	int j = 0;
	BN_CTX* ctx;
	unsigned char* ret;
	int flag = 0;
	
	//Checks 
	if(pieces == NULL || n_pieces <= 0 || outlen == NULL)
		return NULL;
	
	//Init. BIGNUM context
	ctx = BN_CTX_new();
	BN_CTX_init(ctx);
	
	secret = BN_new();
	if(secret == NULL)
		goto error;
	temp = BN_new();
	if(temp == NULL)
		goto error;
	BN_x_j = BN_new();
	if(BN_x_j == NULL)
		goto error;
	BN_x_i = BN_new();
	if(BN_x_j == NULL)
		goto error;
	rem = BN_new();
	if(rem == NULL)
		goto error;
	modulus = BN_new();
	if(modulus == NULL)
		goto error;
	
	get_max_value(modulus, DIM_KEY);
	
	/*-----DEBUG-----*/
	printf("Max val = ");
	BN_print_fp(stdout, modulus);
	printf("\n");
	
	BN_zero(secret);
	BN_zero(modulus);
	BN_zero(rem);
	
	//Compute the value of x0 through Lagrange Polynomial 
	for(i = 0; i < n_pieces; i++){
	
		//Save f(x_i) in temp
		BN_bin2bn(pieces[i].piece, pieces[i].dim_piece, temp);
		//Save x_i in BN_x_i
		int2BN(pieces[i].x, BN_x_i);
		for(j = 0; j < n_pieces; j++){
			if(i == j)
				continue;
			//Save x_j in BN_x_j
			int2BN(pieces[j].x, BN_x_j);
			//Set BN_x negative
			BN_set_negative(BN_x_j, 1);
			//Multiplication: [f(x_i) * -x_j]
			BN_mul(temp, BN_x_j, temp, ctx);
			//Subtraction: (x_i - x_j) and store in x_j
			BN_add(BN_x_j, BN_x_i, BN_x_j);			//Just a sum, because we set BN_x_j negative
			
			//Division: [f(x_i) * -x_j] / (x_i - x_j)
			BN_div(temp, rem, temp, BN_x_j, ctx);
			
			if(BN_is_zero(rem) == 0)
				flag = 1;
		}
		BN_add(secret, temp, secret);	
	}
	
	*outlen = BN_num_bytes(secret);
	ret = calloc(*outlen, sizeof(char));
	BN_bn2bin(secret, ret);
	if(flag == 1)
		//ret[*outlen - 2] += 1;
	
	//Cleanup
	BN_clear_free(secret);
	BN_clear_free(temp);
	BN_clear_free(BN_x_i);
	BN_clear_free(rem);
	BN_clear_free(modulus);
	BN_clear_free(BN_x_j);
	BN_CTX_free(ctx);
	
	return ret;
	
error:
	fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
	if(secret != NULL)
		BN_clear_free(secret);
	if(temp != NULL){
		BN_clear_free(temp);
	}
	if(BN_x_i != NULL){
		BN_clear_free(BN_x_i);
	}
	if(BN_x_j != NULL){
		BN_clear_free(BN_x_j);
	}
	if(rem != NULL){
		BN_clear_free(rem);
	}
	if(modulus != NULL){
		BN_clear_free(modulus);
	}
	if(ctx != NULL){
		BN_CTX_free(ctx);
	}
		
	return NULL;

}


int main(){		
	unsigned char* recovery;
	struct secret_pieces* prova;
	int i = 0;
	int ret;
	int total;
	int redundancy = 5;
	unsigned char* temp = malloc(32 + redundancy);
	while(1){
		RAND_bytes(temp, 32 + redundancy);
		//print_bytes(temp, 32 + redundancy);
		prova = secret_sharing(temp,32 + redundancy, 5, 4);
		
		/*
		for(i = 0; i < 4; i++){
			printf("Iteration %i:\t", i);
			printf("X = %i piece = ", prova[i].x);
			print_bytes(prova[i].piece, prova[i].dim_piece);
		}
		*/
		
		recovery = secret_recovery(prova, 5, &total);
		//print_bytes(recovery, total);
		//recovery[strlen(secret)-1] = '\0';
		if(memcmp(temp, recovery, 32) != 0)
			break;
		i++;
	}
	printf("Risultato ricostruito correttamente: %i volte\n", i);
	//printf("Risultato ricostruito: %s\n", recovery);
	
}	
