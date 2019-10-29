// Comprova el funcionament de la PBKDF 
// Xifrem amb openssl  ->  dexifrem amb aquest programa
//
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void read_file (char *fname, char *buf, int *len)
{

	FILE *f;
    	unsigned char inbuf[10];
	int tot,n;
	
	tot=0;

	f=fopen(fname,"rb");
	while (!feof(f)) {
	   n = fread(&inbuf, sizeof(unsigned char), 1, f);
	   if (n>0) {
		memcpy(&buf[tot],inbuf,n);
		tot +=n;
	   }
	}
	fclose(f);
	*len=tot;
	printf("PPP  %s\n",buf);
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
	unsigned char ct[100], ctf[100];   // Cipher text
	unsigned *pt; //Plain text
	int ctlen, tmplen, ptlen;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[8];
	EVP_CIPHER_CTX ctx;
	FILE *out;
  	unsigned char salt[] = {0,0,0,0,0,0,0,0};	
	int i,status;
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


	read_file("carla.bin",ct,&ctlen);

	printf("Mida ct %d \n",ctlen);

	printf("ct: ");
    	for (i = 1; i <= ctlen; i++){
        	printf("%02X", ct[i]);
	}
	printf("\n");

   	for (i = 1; i <= (ctlen-15); i++){
		ctf[i-1] = ct[i+15];
	}

	ctlen = ctlen -16;
	

	printf("ctf: ");
    	for (i = 0; i < ctlen; i++){
        	printf("%02X", ctf[i]);
	}
	printf("\n");



    	EVP_DecryptInit(&ctx, EVP_rc2_ecb(), key, iv);

    	pt = (unsigned char *)malloc(ctlen + EVP_CIPHER_CTX_block_size(&ctx) + 1);


    	EVP_DecryptUpdate(&ctx, pt, &ptlen, ctf, ctlen);
	printf("Texte dexifrat: %s \n",pt);
    	status=EVP_DecryptFinal(&ctx, pt, &ptlen);   //Per comprovar el decrypt OK
	
	EVP_CIPHER_CTX_cleanup(&ctx);

	if (status==1) {
	   printf("Texte dexifrat correcte \n");
	}  else {
	   printf("Passwd incorrecte \n");
	}

	printf("Mida darrer bloc  %d \n",ptlen);

	printf("Aquest programa funciona bé si prèviament has fet \n \t\t echo \"El password és Carla\"| openssl enc -rc2-ecb -out carla.bin -pass pass:Carla -S 0 \n"); 
}
