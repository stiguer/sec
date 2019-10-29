#include <openssl/bn.h>
#include <openssl/bio.h>
# define SIZE 100

int main() {

	int top; // -1; msb can be zero
		 // 0; msb = 1
		 // 1; 2 msb = 1
	int bottom; // 1; number odd
	BIO  *bio_out;

	BIGNUM *a, *b;
	a = BN_new();
	b = BN_new();

	top=-1;
	bottom=1;
	BN_rand(a, SIZE, top,bottom); 
	BN_rand(b, SIZE, top,bottom); 


	printf("Longitud a: %d \n", BN_num_bits(a));
	printf("Longitud b: %d \n", BN_num_bits(b));

	printf("Number a: %s \n",BN_bn2dec(a));
	printf("Number b: %s \n",BN_bn2dec(b));

	BN_copy(a,b);

	printf("Number a: %s \n",BN_bn2dec(a));
	printf("Number b: %s \n",BN_bn2dec(b));

	BN_dec2bn(&b, "3");
	printf("Longitud b: %d \n", BN_num_bits(b));
	printf("Number b: %s \n",BN_bn2dec(b));

	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BN_print(bio_out, a);
	printf("\nNumber a hex: %s \n",BN_bn2hex(a));


	BN_free(b);
	BN_free(a);

}

