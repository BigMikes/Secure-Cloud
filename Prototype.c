//Fa SHA256 sul buffer source e se name_file diverso da NULL lo fa pure sul file concatendando 
unsigned char* do_hash(unsigned char* source, char* name_file);

//Verifica l'integrità
int verify_hash(unsigned char* source, char* name_file ,unsigned char* hash_val);

//Cifra con AES-x, simmetrico
unsigned char* sym_crypto(unsigned char* source, char* name_file, unsigned char* key);

//Cifratura simmetrica RSA 
unsigned char* sym_crypto(unsigned char* source, unsigned char* key);
