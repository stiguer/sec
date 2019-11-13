// Signa un text
// 
//
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PRIVKEY_FILE "rsaprivkey.pem"
#define PUBKEY_FILE "rsapubkey.pem"

void handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

#define READSIZE 1024
/* Returns 0 on error, file contents on success */


int main() {

  int i,len,lend; 
  FILE                     *fp;
  BIO                      *out;
  RSA	  		   *rsakey, *rsapubkey;
  unsigned char * from, *to_nopad; 
  unsigned char to[1024];
  unsigned char * sigret;
  int  siglen,olen;
  int ver;
  EVP_MD_CTX *ctx;
  unsigned char *ret;
  unsigned char text[123]="Hola, bon dia";

  ctx=EVP_MD_CTX_new();
  OpenSSL_add_all_algorithms();
  if (!(ret = (unsigned char *)malloc(EVP_MAX_MD_SIZE)))
        return NULL;

  EVP_DigestInit(ctx, EVP_sha1());

   /* open stdout */
  if (!(out = BIO_new_fp(stdout, BIO_NOCLOSE)))
    int_error("Error creating stdout BIO");

  /* Llegint RSA key  */
  if (!(fp = fopen(PUBKEY_FILE, "r")))
    int_error("Error reading  PUBKEY file");
  if (!(rsapubkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)))
    int_error("Error reading PUBKEY in file");
  fclose(fp);


  // Part privada
  // man -s 3 pem  
  if (!(fp = fopen(PRIVKEY_FILE, "r")))
    int_error("Error reading  PRIVKEY file");
 
  if (!(rsakey = PEM_read_RSAPrivateKey(fp, NULL, NULL, "1234")))
    int_error("Error reading PRIVKEY in file");

  fclose(fp);

  printf("Signant....mida %d  \n\n",RSA_size(rsakey));

  sigret = (unsigned char *) malloc(RSA_size(rsakey));


  EVP_DigestUpdate(ctx, text, strlen(text));
  EVP_DigestFinal(ctx, ret, &olen);
  //if (!(RSA_sign(NID_sha1,"0123456789012345678901234567890123456789", 40, sigret, &siglen, rsakey)))
  if (!(RSA_sign(NID_sha1,ret, olen, sigret, &siglen, rsakey)))
    int_error("Error signant");

  printf("Signature length: %d\n",siglen);
  fp = fopen("./signatura.der","w");
  fprintf(fp,"%s",sigret);
  fclose(fp);
  printf("Signature: %s",sigret);
  printf("\n\nVerificant .... \n");

  //ver = RSA_verify(NID_sha1,"0123456789012345678901234567890123456789", 40, sigret, siglen, rsapubkey);
  ver = RSA_verify(NID_sha1,ret, olen, sigret, siglen, rsapubkey);
  printf("Verificant Resultat %d \n", ver);


  printf("També pot verificar-se: \n echo -n \"Hola, bon dia\" | openssl dgst -sha1 -verify rsapubkey.pem -signature signatura.der \n");

}

