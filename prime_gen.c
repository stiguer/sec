#include <openssl/bn.h>

int main(int argc, char * argv[]) {

	int nbits; 
	int safe=1;  // (p-1)/2 also prime
	if (argc != 2) {
		printf("Usage:  %s number_bits \n", argv[0]);
		exit(0);
        }

	BIGNUM *r;
	r = BN_new();
	nbits=atoi(argv[1]);

	if (!RAND_load_file("/dev/urandom", 2048))
		return 0;

	BN_generate_prime_ex(r, nbits, safe, NULL, NULL, NULL);
	printf("%s \n",BN_bn2dec(r));
	BN_free(r);
}

