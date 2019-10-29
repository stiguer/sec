#include <openssl/evp.h>

void read_file (char *fname, char *buf, int *len)
{

	FILE *f;
    	unsigned char inbuf[10];
	int tot,n;
	
	tot=0;

	f=fopen(fname,"r");
	while (!feof(f)) {
	   n = fread(&inbuf, sizeof(unsigned char), 1, f);
	   if (n>0) {
		memcpy(&buf[tot],inbuf,n);
		tot +=n;
	   }
	}
	fclose(f);
	*len=tot;
}

int main(int argc, char** argv) {
	int i;
	unsigned char et[100];   // Encoded text
	unsigned char *dt;   // Decoded text
	int etlen,dtlen;


	printf("openssl base64 -in missatge.txt > missatge.b64\n\n");
	read_file("missatge.b64",et,&etlen);

	printf("Encoded text length: %d \n",etlen);

        dt = (unsigned char *)malloc(etlen);

	dtlen = EVP_DecodeBlock(dt,et,etlen); 

	printf("Decoded text length: %d \n",dtlen);
	printf("Decoded text:  %s", dt);
	printf("Decoded text (Hex):   ", dt);
	for (i=0; i<dtlen; i++){
		printf("%02x",dt[i]);
	}
	printf("\n");

	exit(0);
}

