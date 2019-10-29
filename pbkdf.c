// Comprova el funcionament de la PBKDF 
//  Xifrem amb aquest programa -> dexifrem amb openssl
//
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void read_file (char *fname)
{

	FILE *f;
    	unsigned char inbuf;

	f=fopen(fname,"rb");
	while (!feof(f)) {
	        fread(&inbuf, sizeof(unsigned char), 1, f);
		printf("%02x",inbuf);
	}
	fclose(f);
}

void print_output(char *fname,char *out,int len)
{
	FILE *f;
	unsigned char salt1[] = "Salted__";
	unsigned char salt2[] = {0,0,0,0,0,0,0,0};
	f=fopen(fname,"wb");
        fwrite(salt1, sizeof(unsigned char), 8, f);
        fwrite(salt2, sizeof(unsigned char), 8, f);
        fwrite(out, sizeof(unsigned char), len, f);
	fclose(f);
}

int main(int argc, char** argv)
{
	unsigned char *ct;   // Cipher text
	unsigned char *pt;   // Plain text
	int ctlen, tmplen, ptlen;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[8];
	char intext[] = "El password és Carla";
	EVP_CIPHER_CTX ctx;
	FILE *out;
  	unsigned char salt[] = {0,0,0,0,0,0,0,0};	
	int i;
	FILE *f;

  
	EVP_CIPHER_CTX_init(&ctx);

	EVP_BytesToKey(EVP_rc2_ecb(), EVP_md5(), salt, "Carla", strlen("Carla"), 1, key,iv);
	printf("Salt: ");
    	for (i = 0; i < sizeof(salt); i++){
        	printf("%02X", salt[i]);
	}
	printf("\n");


	printf("Key: ");
    	for (i = 0; i < 16; i++){
        	printf("%02X", key[i]);
	}
	printf("\n");

	printf("IV: ");
    	for (i = 0; i < sizeof(iv); i++){
        	printf("%02X", iv[i]);
	}
	printf("\n");


//	read_file("carla.bin");


	EVP_EncryptInit(&ctx, EVP_rc2_ecb(),  key, iv);
        
	ct = (unsigned char *)malloc(strlen(intext) + EVP_CIPHER_CTX_block_size(&ctx));
	EVP_EncryptUpdate(&ctx, &ct[0], &ctlen, intext, strlen(intext));
	EVP_EncryptFinal(&ctx, &ct[ctlen], &tmplen);
	ctlen += tmplen;
	print_output("./a", ct,ctlen);

	
	printf("L'arxiu  a   es pot dexifrar fent:  \n   \t  openssl enc -rc2-ecb -pass pass:Carla -d -S 0 -in a \n");


/*
    	EVP_DecryptInit(&ctx, EVP_rc2_ecb(), key, iv);

    	pt = (unsigned char *)malloc(ctlen + EVP_CIPHER_CTX_block_size(&ctx) + 1);


    	EVP_DecryptUpdate(&ctx, pt, &ptlen, ct, ctlen);


	EVP_CIPHER_CTX_cleanup(&ctx);

	//printf("Texte dexifrat: %s \n",pt);
*/

}
