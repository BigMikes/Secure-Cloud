#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <unistd.h>

#define SSL_CIPHERS "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS"
//#define SSL_CIPHERS "DHE-DSS-AES128-SHA256"

SSL_CTX* create_SSL_context(const char* cert_file, const char* prvkey_file);
SSL* bind_socket_to_SSL(SSL_CTX* ctx, int sock);
int client_connect(SSL* ssl_sock);
int server_accept(SSL* ssl_sock);
int secure_read(int fd, void* buffer, int count, SSL* sock);
int secure_write(int fd, void* buffer, int count, SSL* sock);
void ssl_context_cleanup(SSL_CTX* ctx);
