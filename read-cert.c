//  Read certificates x509
//  Print outs some info
//  Partly from  Example 10-6  of  "Network Security with OpenSSL" (O'Reilly Ed.)

#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
void handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}
#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

#define CERT_FILE "./DNIeCerts/cert_firma.pem"

int main() {

  int i; 
  X509                     *cert;
  X509_NAME                *name;
  FILE                     *fp;
  BIO                      *out;
  EVP_PKEY  		   *pubkey;
  

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

   /* open stdout */
  if (!(out = BIO_new_fp(stdout, BIO_NOCLOSE)))
    int_error("Error creating stdout BIO");

  /* read in the CA certificate */
  if (!(fp = fopen(CERT_FILE, "r")))
    int_error("Error reading CERT certificate file");
  if (!(cert = PEM_read_X509(fp, NULL, NULL, NULL)))
    int_error("Error reading CERT certificate in file");
  fclose(fp);

  /* print out the subject name and subject alt name extension */
  if (!(name = X509_get_subject_name(cert)))
    int_error("Error getting subject name from request");

  X509_NAME_print(out, name, 0);
  printf("\n");

  printf("Version; Estructura ASN1 INTEGER d'1 byte \n");
  printf("Ver %u\n", X509_get_version(cert));
  printf("\n");
  printf("Serial Number; Estructura ASN1 INTEGER de 3 bytes \n");
  printf("Serial Num %x\n", X509_get_serialNumber(cert));
  printf("\n");
  X509_print(out, cert);
}

