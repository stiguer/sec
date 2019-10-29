#include <openssl/bn.h>


static void prime_status(int code, int arg, void *cb_arg)
{
    if (code == 0)
         printf("\n * Found potential prime #%d ...", (arg + 1));
    else if (code == 1 && arg && !(arg % 10))
         printf(".");
    else
         printf("\n Got one!\n");
}

BIGNUM *generate_prime(int bits, int safe)
{
    char    *str;
    BIGNUM *prime;
    printf("Searching for a %sprime %d bits in size ...", (safe ?  "safe " : ""), bits);
    // BIGNUM *BN_generate_prime(BIGNUM *ret, int num, int safe, BIGNUM *add,
    //             BIGNUM *rem, void (*callback)(int, int, void *), void *cb_arg);
    //
    // safe;  if not NULL;  (prime -1 /2) is also prime
    // num:  Number of bits
    // add: if not NULL;  prime % add == rem

    prime = BN_generate_prime(NULL, bits, safe, NULL, NULL, NULL, NULL);
    if (!prime)
         return NULL;
    str = BN_bn2dec(prime);
    if (str)
    {
         printf("Found prime: %s\n", str);
    }
    return prime;
}

BIGNUM * random_g (BIGNUM *p)
{

}

int main(int argc, char * argv[]) {
	BIGNUM *p;
	int nbits; 
	int is,flag; 
        BIGNUM * pm1;
        BIGNUM *q;
        BIGNUM *qx2;
        BIGNUM *g;
        BIGNUM *gtoq;
        BIGNUM *one;
        BIGNUM *two;
	BN_CTX *ctx;
	BIGNUM *order;
	BIGNUM *g2o;
	ctx = BN_CTX_new();
        pm1=BN_new(); one=BN_new(); two=BN_new();q=BN_new(); g=BN_new(); gtoq=BN_new(); qx2=BN_new();
	order=BN_new(); g2o=BN_new();
        BN_dec2bn(&one, "1"); BN_dec2bn(&two, "2"); 

	p=BN_new();

	if (argc != 2) {
		printf("Usage:  %s number_bits \n", argv[0]);
		exit(0);
        }

	nbits=atoi(argv[1]);
	p =  generate_prime(nbits,1);

	is  = BN_is_prime(p,10,NULL,NULL,NULL);
   	BN_sub(pm1, p, one); 
   	BN_rshift(q, pm1, 1); 


	printf("%s \n",BN_bn2dec(p));
	printf("Is prime and secure:  %d with error les than 0.0000009 (0.25^10)\n",is);
	printf("q:  %s \n",BN_bn2dec(q));

	flag=0;
	while (flag==0){   // Enforce  g != 1
		BN_rand_range(g,p);
		if (BN_cmp(g,one)!=0){
			flag=1;
		}
	}
	printf("g:  %s \n",BN_bn2dec(g));



	BN_mod_exp(g2o, g,two,p,ctx);
	if ( BN_cmp(g2o,g)==0 ) {  
		BN_copy(order,two);
	} else {
		BN_mod_exp(g2o, g,q,p,ctx);
		if ( BN_cmp(g2o,g)==0 ) {  
			BN_copy(order,q);
		} else {
			BN_mul(qx2,q,two,ctx);
			BN_copy(order,qx2);
		}
	} 

	printf("Order of g:  %s \n",BN_bn2dec(order));

	BN_mod_exp(g2o, g,qx2,p,ctx);
	printf("g^2q:  %s \n",BN_bn2dec(g2o));
}

