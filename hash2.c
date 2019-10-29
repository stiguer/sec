#include <openssl/evp.h>
#define READSIZE 1024
void print_hex(unsigned char *bs, unsigned int n)
{
    int i;
    for (i = 0; i < n; i++)
        printf("%02x", bs[i]);
}

int hash_a_file_sha1(char *fname)
{
    FILE            *f = fopen(fname, "rb");
    const EVP_MD *m;
    EVP_MD_CTX    *ctx;
    unsigned char *ret;
    int n,olen;
    unsigned char *buf = NULL, *last = NULL;
    unsigned char inbuf[READSIZE];
    int count=0;
	ctx=EVP_MD_CTX_new();

    OpenSSL_add_all_digests();
    if (!(ret = (unsigned char *)malloc(EVP_MAX_MD_SIZE)))
        return NULL;

    EVP_DigestInit(ctx, EVP_sha1());
    printf("Digest Size %d bytes (%d bits)  \n",EVP_MD_CTX_size(ctx), 8*EVP_MD_CTX_size(ctx));

   while (n = fread(inbuf, sizeof(unsigned char), READSIZE, f)){
	printf("Update %d.  %d bytes\n",count,n);
	count++;
    	EVP_DigestUpdate(ctx, inbuf, n);
   }
   fclose(f);

   EVP_DigestFinal(ctx, ret, &olen);

   printf("SHA1(%s)= ", fname);
   print_hex(ret, olen);
   printf("\n");
   return 1;

}

int main(int argc, char *argv[])
{

   if (argc < 2) {
	printf("Entra el nom de l'arxiu \n");
   } else {
   	hash_a_file_sha1(argv[1]);
   }
   return 0;
}

