#include <openssl/bn.h>
#include <openssl/rsa.h>
#define SIZE 100


int main() {
	RSA *key;
	BN_CTX *ctx;
	BIGNUM *pq;
	BIGNUM *n,*e,*d,*p,*q;

	pq=BN_new();
	ctx = BN_CTX_new();
	key =  RSA_generate_key(SIZE,3,NULL,NULL);
	RSA_get0_key(key, &n, &e, &d);
	RSA_get0_factors(key,  &p, &q);

	printf("p: %s \n",BN_bn2dec(p));
	printf("q: %s \n",BN_bn2dec(q));
	printf("n: %s \n",BN_bn2dec(n));
	printf("d: %s \n",BN_bn2dec(d));
	printf("e: %s \n",BN_bn2dec(e));

	BN_mul(pq,p,q,ctx);
	printf("n check: %s \n",BN_bn2dec(pq));
}

