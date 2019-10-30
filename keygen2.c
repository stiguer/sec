#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/bio.h>

//  Same as keygen.c but reading DH params from file

int main() {

	DH *dh;
	FILE *f;
	BIGNUM *gtox,*p,*q,*g,*priv_key,*pub_key;
	BN_CTX *ctx;
	BIO *bio;

	bio=BIO_new_file("dhpar.pem","r");

	gtox=BN_new();
	ctx = BN_CTX_new();
	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	DH_get0_pqg(dh,&p,&q,&g);
	printf("Prime: %s \n\n",BN_bn2dec(p));
	DH_generate_key(dh);
	DH_get0_key(dh,&pub_key,&priv_key);
	printf("Private Key: %s \n\n",BN_bn2dec(priv_key));
	printf("Public Key: %s \n\n",BN_bn2dec(pub_key));

	// Doublecheck the public key. Effectively   g^x
	BN_mod_exp(gtox, g, priv_key, p, ctx);
	printf("Public Key (gtox): %s \n\n",BN_bn2dec(gtox));
}

