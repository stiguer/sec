#include <openssl/bn.h>
// Problemes, ja que no tots els N donen  factors p t.q. són coprimers amb e=3 

BIGNUM * random_g (BIGNUM *p)
{

}

int main(int argc, char * argv[]) {
	BIGNUM *n, *c, *dcs, *zero, *exp, *one, *s, *t, *a , *m;
	int nbits; 
	int is,flag,i,j,bl; 
     	char buffer[100];
	char num[1000];
	FILE *in ;
	int MB=8;  //  Macroblock size in number of bytes
        BIGNUM * e;
	BN_CTX *ctx;
	ctx = BN_CTX_new();
        n=BN_new(); e=BN_new(); c=BN_new(); dcs=BN_new(); zero=BN_new(); exp=BN_new();
	one=BN_new(); s=BN_new(); t=BN_new(); a=BN_new(); 
	m=BN_new(); 
        BN_dec2bn(&e, "17"); // Uses  e=17 
        BN_dec2bn(&dcs, "256"); 
        BN_dec2bn(&zero, "0"); 
        BN_dec2bn(&one, "1"); 


	if (argc != 3) {
		printf("Usage:  %s clear_text_file  N \n", argv[0]);
		exit(0);
        }
	BN_dec2bn(&n,argv[2]);



	in = fopen(argv[1],"r"); 
        fgets(buffer, 100, in);
        fprintf(stderr,"first and unique line of %s: %s\n", argv[1],buffer);
        fclose(in);

	bl=strlen(buffer)-1;
	fprintf(stderr,"Buffer length: %d \n",bl);

	for (i=0; i<bl;i++){
		fprintf(stderr,">> %c %d\n",buffer[i],buffer[i]);
	}

	// Padding
	i=bl;
	while (i%MB != 0 ) {
		buffer[i]=(int) NULL;
		i++;
	}

	for (j=0; j<= (int) bl/MB; j++){
	  //printf("Macrobloc  %d\n",j);
	  BN_copy(m,zero);
	  BN_copy(exp,zero);
	  for (i=0; i<MB ; i++) {
		//printf(">> %c %d\n",buffer[i+j*MB],buffer[i+j*MB]);
		//  m = \sum_i  a_i * 256^{i}
		//                    ______
		//                       |
		//                       |-> t
		//              _____________
		//                   |
		//                   |->  s
		//
		//  c = m^e  mod N
		BN_exp(t,dcs,exp,ctx);
		
		sprintf(num,"%d",buffer[i+j*MB]);
		BN_dec2bn(&a,num);

		BN_mul(s, a, t,ctx);
		BN_add(m, m, s);

		BN_add(exp,exp,one);
	  }
	  fprintf(stderr,"m:  %s \n",BN_bn2dec(m));
	  BN_mod_exp(c,m,e,n,ctx);
	  printf("Word: %s \n", BN_bn2dec(c));
	}
}

