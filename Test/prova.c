#include "utils.h"

#define HASH_DIM EVP_MD_size(EVP_sha256())
#define MAX_USR_NAME 20


int find_usr_pwd(unsigned char* username, unsigned char* pwd){
    FILE *fp;
    int lines = 0;   // count how many lines are in the file
    int j = 0;
    int c;
    unsigned char* hash_pwd;
    char tmp_user[MAX_USR_NAME]; 		//Dimensione massima del nome utente 
    char tmp_pwd[HASH_DIM];
    int ret;
    
    fp = fopen("pwd.txt", "r");
    if(fp == NULL)
    	return -1;
    
    while(!feof(fp)) {
        c=fgetc(fp);
        if(c == '\n')
            lines++;
    }
    
    if(lines == 0){
    	fclose(fp);
    	return -1;
    }
    
    hash_pwd = do_hash(pwd, strlen(pwd), NULL);
    
    rewind(fp);  // Line I added
        // read each line and put into accounts
    while(j != lines - 1) {
        fscanf(fp, "%s ", tmp_user);
        fread(tmp_pwd, HASH_DIM, 1, fp);
        if(strcmp(tmp_user, username) == 0){
        	ret = CRYPTO_memcmp(hash_pwd, tmp_pwd, HASH_DIM);
        	free(hash_pwd);
        	fclose(fp);
        	return (ret == 0)? 1 : 0;
        }
       	j++;
    }
    free(hash_pwd);
    fclose(fp);
    return -1;
}


int add_usr_pwd(unsigned char* username, unsigned char* pwd){
    FILE *fp;
    unsigned char* hash_pwd;
    int ret;
    
    fp = fopen("pwd.txt", "a");
    if(fp == NULL)
    	return -1;
    
    hash_pwd = do_hash(pwd, strlen(pwd), NULL);
    
    fprintf(fp, "%s ", username);
    fwrite(hash_pwd, HASH_DIM, 1, fp); 
    fprintf(fp, "\n");
    fflush(fp);
    free(hash_pwd);
    fclose(fp);
    return 1;
}


int main(){
	int ret;
	add_usr_pwd("Silvia", "pipa");
	add_usr_pwd("Giulio", "ciao");
	
	ret = find_usr_pwd("Silvia", "pipa");
	if(ret == 1)
		printf("Authenticated Silvia pipa\n");
	else
		printf("Not Authenticated Silvia pipa\n");
	
	ret = find_usr_pwd("Silvi", "pipa");
	if(ret == 1)
		printf("Authenticated\n");
	else
		printf("Not Authenticated\n");
	ret = find_usr_pwd("Silvia", "ipa");
	if(ret == 1)
		printf("Authenticated\n");
	else
		printf("Not Authenticated\n");
	ret = find_usr_pwd("Giulio", "silvia");
	if(ret == 1)
		printf("Authenticated Giulio silvia\n");
	else
		printf("Not Authenticated\n");	
}
