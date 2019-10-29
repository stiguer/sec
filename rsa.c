#include <openssl/bn.h>
#define SIZE 300
/*
 *  Computa paràmetres RSA
 *
*/

int d_check_modular_inverse(BIGNUM  * d, BIGNUM  * e, BIGNUM  * totient, BN_CTX *ctx)
{
  int flag;

  BIGNUM *res;
  res=BN_new();

  BN_mod_mul(res,e,d,totient,ctx);

  flag=BN_is_one(res);

  printf("Modular d·e is one ??  %d \n",flag);

  return flag;

}

int is_prime_secure (BIGNUM * p)
{
   BIGNUM * pm1;
   BIGNUM * pm1o2;
   BIGNUM *one;
   pm1=BN_new(); one=BN_new();
   pm1o2=BN_new(); 
   BN_dec2bn(&one, "1"); 
   BN_sub(pm1, p, one); 
   BN_rshift(pm1o2, pm1, 1); 


  if (BN_is_prime(pm1o2, BN_prime_checks, NULL,NULL,NULL) == 1){
	printf("Effectively, (p-1)/2 , %s is prime \n",BN_bn2dec(pm1o2));
  } else {
	printf("Care, (p-1)/2 , %s is NOT prime \n",BN_bn2dec(pm1o2));
  }

}

int main() {
	BIGNUM *p;
	BIGNUM *pm1;
	BIGNUM *q;
	BIGNUM *qm1;
	BIGNUM *n;
	BIGNUM *totient;
	BIGNUM *one;
	BIGNUM *e;
	BIGNUM *d;

	BN_CTX *ctx;
	p=BN_new();
	pm1=BN_new();
	q=BN_new();
	qm1=BN_new();
	n=BN_new();
	ctx = BN_CTX_new();
	one=BN_new();
	totient=BN_new();
	e=BN_new();
	d=BN_new();

	BN_generate_prime_ex(p, SIZE, 1, NULL, NULL, NULL);
	BN_generate_prime_ex(q, SIZE, 1, NULL, NULL, NULL);
	BN_mul(n,p,q,ctx);

	BN_dec2bn(&one, "1");
	BN_dec2bn(&e, "3");
	BN_sub(pm1,p,one);
	BN_sub(qm1,q,one);
	BN_mul(totient,pm1,qm1,ctx);

	BN_mod_inverse(d,e,totient,ctx);

	d_check_modular_inverse(d,e,totient,ctx);

	BN_CTX_free(ctx);

	printf("p: %s \n",BN_bn2dec(p));
	printf("q: %s \n",BN_bn2dec(q));
	printf("n: %s \n",BN_bn2dec(n));
	printf("totient: %s \n",BN_bn2dec(totient));
	printf("d: %s \n",BN_bn2dec(d));

	is_prime_secure(p);
	is_prime_secure(q);
}

