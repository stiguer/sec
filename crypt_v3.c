//  Exemple de xifrat i dexifrat en bloc
//  Extret de les man pages
//
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void select_random_key(unsigned char *key, int b)
{
    int i;
    RAND_bytes(key, b);
    printf("Max Key Length  %d \n",b);
    for (i = 0; i < b - 1; i++){
        printf("%02X", key[i]);
    }
    printf("%02X\n", key[b - 1]);
}

int main(int argc, char** argv)
{
	unsigned char *ct;   // Cipher text
	unsigned char *pt;   // Plain text
	int ctlen, tmplen, ptlen;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[] = {};
	char intext[] = "Això és el texte en clar";
	EVP_CIPHER_CTX *ctx;
 	ctx=EVP_CIPHER_CTX_new();	

	FILE *out;
  	
	select_random_key(key, EVP_MAX_KEY_LENGTH);

	EVP_EncryptInit(ctx, EVP_bf_ecb(),  key, iv);


	printf("Longitud de clau de EVP_bf_ecb(): %d \n",EVP_CIPHER_CTX_key_length(ctx));
	printf("Això implica que els darrers %d bytes de la clau no s'empren:  \n",EVP_CIPHER_CTX_key_length(ctx));

	printf("Texte en clar:  %s \n", intext);
	printf("Mida del texte en clar %d \n", strlen(intext));
    ct = (unsigned char *)malloc(strlen(intext) + EVP_CIPHER_CTX_block_size(ctx));

	EVP_EncryptUpdate(ctx, &ct[0], &ctlen, intext, strlen(intext));
	EVP_EncryptFinal(ctx, &ct[ctlen], &tmplen);

	ctlen += tmplen;
	out = fopen("./out.crypt", "wb");
	fwrite(ct, 1, ctlen, out);
	fclose(out);

	printf("Texte xifrat:  %s \n", ct);
	printf("Mida del texte xifrat %d \n", ctlen);
	printf("Es pot dexifrar (des de línia de comandes): \n", ctlen);
	printf("\t openssl bf-ecb -in out.crypt -K clau_hexadecimal   -d \n", ctlen);


    EVP_DecryptInit(ctx, EVP_bf_ecb(), key, iv);

    pt = (unsigned char *)malloc(ctlen + EVP_CIPHER_CTX_block_size(ctx) + 1);


    EVP_DecryptUpdate(ctx, pt, &ptlen, ct, ctlen);

    if (!EVP_DecryptFinal(ctx,&pt[ptlen],&tmplen)) {
            printf("Error decrypting on padding \n");
    } else {
            printf("Succesful decryption\n");
            
    }
    ptlen+=tmplen;

	EVP_CIPHER_CTX_cleanup(ctx);

	printf("Texte dexifrat: %s \n",pt);
	printf("Texte dexifrat Longitud: %d \n",ptlen);

	return 1;
	 
}    
