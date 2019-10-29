#include <openssl/bn.h>

int main() {

	int lena;
	unsigned char * buf = malloc(8*sizeof(char));

	BIGNUM *a;
	a=BN_new();

	BN_dec2bn(&a,"50462976");
	printf("p: %s \n",BN_bn2dec(a));
	lena = BN_bn2bin(a,buf);
	// 50462976 is 3020100 in hex
	printf("Length: %d\n\n",lena);

	
	printf("%02X",buf[0]);
	for (int i=1;i<lena;i++)
	{
		printf(" : %02X",buf[i]);
	}
	printf("\n");
	// buf[0] is 04
	// buf[1] is 03
	// buf[2] is 02
	// buf[3] is 00
	// So it is little endian

	BN_free(a);

}

