//  Exemple de  Network Security with OpenSSL
#include <openssl/evp.h>
unsigned char *simple_digest(char *alg, char *buf, unsigned int len, int *olen)
{
    const EVP_MD *m;
    EVP_MD_CTX    *ctx;
    unsigned char *ret;
    int nb;
	ctx=EVP_MD_CTX_new();
    OpenSSL_add_all_digests();
    if (!(m = EVP_get_digestbyname(alg)))
        return NULL;
    if (!(ret = (unsigned char *)malloc(EVP_MAX_MD_SIZE)))
        return NULL;

    EVP_DigestInit(ctx, m);
    printf("Maximum Digest Size %d bytes (%d bits)  \n",EVP_MAX_MD_SIZE, 8*EVP_MAX_MD_SIZE);
    printf("%s  Digest Size %d bytes (%d bits)  \n",alg,EVP_MD_CTX_size(ctx), 8*EVP_MD_CTX_size(ctx));
    EVP_DigestUpdate(ctx, buf, len);
    EVP_DigestFinal(ctx, ret, olen);
    return ret;
}

void print_hex(unsigned char *bs, unsigned int n)
{
    int i;
    for (i = 0; i < n; i++)
        printf("%02x", bs[i]);
}


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

/* Returns NULL on error, the digest on success */
unsigned char *process_file(FILE *f,  int *olen)
{
    int            filelen;
    unsigned char *ret, *contents = read_file(f, &filelen);
    if (!contents)
        return NULL;
    ret = simple_digest("sha1", contents, filelen, olen);
    free(contents);
    return ret;
}

/* Returns 0 on failure, 1 on success */
int process_file_by_name(char *fname)
{
    FILE            *f = fopen(fname, "rb");
    unsigned int olen;
    unsigned char *digest;
    if (!f)
    {
         perror(fname);
         return 0;
    }
    digest = process_file(f, &olen);
    if (!digest)
    {
         perror(fname);
         fclose(f);
         return 0;
    }
    fclose(f);
    printf("SHA1(%s)= ", fname);
    print_hex(digest, olen);
    printf("\n");
    return 1;
}

int main(int argc, char *argv[])
{
   if (argc < 2) {
	printf("Entra el nom de l'arxiu \n");
   } else {
   	process_file_by_name(argv[1]);
   }
   return 0;
}

