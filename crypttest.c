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
	EVP_CIPHER_CTX ctx;
	FILE *out;
  	
	select_random_key(key, EVP_MAX_KEY_LENGTH);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit(&ctx, EVP_rc4(),  key, iv);


	printf("Longitud de clau de EVP_bf_ecb(): %d \n",ctx.key_len);
	printf("Això implica que els darrers %d bytes de la clau no s'empren:  \n",EVP_MAX_KEY_LENGTH-ctx.key_len);

	printf("Texte en clar:  %s \n", intext);
	printf("Mida del texte en clar %d \n", strlen(intext));
        ct = (unsigned char *)malloc(strlen(intext) + EVP_CIPHER_CTX_block_size(&ctx));

	EVP_EncryptUpdate(&ctx, &ct[0], &ctlen, intext, strlen(intext));
printf("Long Update %d \n",ctlen);
	//EVP_EncryptFinal(&ctx, &ct[ctlen], &tmplen);
//printf("Long final %d \n",tmplen);

//	ctlen += tmplen;
	out = fopen("./out.crypt", "wb");
	fwrite(ct, 1, ctlen, out);
	fclose(out);

	printf("Texte xifrat:  %s \n", ct);
	printf("Mida del texte xifrat %d \n", ctlen);
	printf("Es pot dexifrar (des de línia de comandes): \n", ctlen);
	printf("\t openssl bf-ecb -in out.crypt -K clau_hexadecimal  -iv 00 -d \n", ctlen);


    	EVP_DecryptInit(&ctx, EVP_rc4(), key, iv);

    	pt = (unsigned char *)malloc(ctlen + EVP_CIPHER_CTX_block_size(&ctx) + 1);


    	EVP_DecryptUpdate(&ctx, pt, &ptlen, ct, ctlen);


	EVP_CIPHER_CTX_cleanup(&ctx);

	printf("Texte dexifrat: %s \n",pt);
	printf("Texte dexifrat Longitud: %d \n",ptlen);

	return 1;
	 
}    
