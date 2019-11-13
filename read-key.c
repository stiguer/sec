// Obté informació d'un parell de claus RSA
// Dexifra un arxiu xifrat
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
unsigned char *read_file(FILE *f, int *len)
{
    unsigned char *buf = NULL, *last = NULL;
    unsigned char inbuf[READSIZE];
    int tot, n;
    tot = 0;
    for (;;)
    {
        n = fread(inbuf, sizeof(unsigned char), READSIZE, f);
        if (n > 0)
        {
             last = buf;
             buf = (unsigned char *)malloc(tot + n);
             memcpy(buf, last, tot);
             memcpy(&buf[tot], inbuf, n);
             if (last)
                 free(last);
             tot += n;
             if (feof(f) > 0)
             {
                 *len = tot;
                 return buf;
             }
        }
        else
        {
             if (buf)
                 free(buf);
             break;
        }
    }
}



int main() {

  int i,len,lend; 
  FILE                     *fp;
  BIO                      *out;
  RSA	  		   *rsakey;
  unsigned char * from, *to_nopad; 
  unsigned char to[1024];
  BIGNUM *n,*p,*q,*d,*e;

  OpenSSL_add_all_algorithms();

   /* open stdout */
  if (!(out = BIO_new_fp(stdout, BIO_NOCLOSE)))
    int_error("Error creating stdout BIO");

  /* Llegint RSA key  */
  if (!(fp = fopen(PUBKEY_FILE, "r")))
    int_error("Error reading  PUBKEY file");
  if (!(rsakey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)))
    int_error("Error reading PUBKEY in file");
  fclose(fp);


  // Part privada
  // man -s 3 pem  
  if (!(fp = fopen(PRIVKEY_FILE, "r")))
    int_error("Error reading  PRIVKEY file");
 
  //if (!(rsakey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)))
  if (!(rsakey = PEM_read_RSAPrivateKey(fp, NULL, NULL, "1234")))
    int_error("Error reading PRIVKEY in file");

  fclose(fp);

  printf("Informació de la clau pública \n");
  RSA_get0_key(rsakey,&n,&e,&d);
  RSA_get0_factors(rsakey,&p,&q);
  printf("Mòdul: %s \n",BN_bn2dec(n));
  printf("Exponent públic: %s \n",BN_bn2dec(e));
  printf("Informació de la clau privada \n");
  printf("Primer p: %s \n",BN_bn2dec(p));
  printf("Primer q: %s \n",BN_bn2dec(q));
  printf("Exponent privat: %s \n",BN_bn2dec(d));

  // Dexifrar  "text_xifrat.bin"
  // Xifrat amb la comanda:  echo "Hola" | openssl rsautl -encrypt -pubin -inkey rsapubkey.pem -out text_xifrat.bin

  printf("Dexifrant .....  \n\n");
  fp = fopen("text_xifrat.bin","rb");
  from = read_file(fp,&len);
  fclose(fp);

  printf("Mida text xifrat: %d\n",len);
 
  if (!(lend=RSA_private_decrypt(len, from, to, rsakey,RSA_PKCS1_PADDING)))
    int_error("Error in signature verification");

  printf("Mida text dexifrat %d \n",lend);
  printf("Text dexifrat: %s \n",to);

  to_nopad = (unsigned char*) malloc(lend);  
  snprintf(to_nopad,lend,"%s\n",to);
  printf("Text dexifrat sense basura residual del buffer ???: %s\n",to_nopad);
}

