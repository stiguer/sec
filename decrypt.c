#include <openssl/bn.h>
#include <msieve.h>

msieve_obj *g_curr_factorization = NULL;

void factor_integer(char *buf, uint32 flags,
		    char *savefile_name,
		    char *logfile_name,
		    char *nfs_fbfile_name,
		    uint32 *seed1, uint32 *seed2,
		    uint32 max_relations,
		    uint64 nfs_lower,
		    uint64 nfs_upper,
		    enum cpu_type cpu,
		    uint32 cache_size1,
		    uint32 cache_size2,
		    uint32 num_threads,
		    uint32 mem_mb, BIGNUM **p, BIGNUM **q) {
	
	char *int_start, *last;
	msieve_obj *obj;
	msieve_factor *factor;
	int count=0;

	/* point to the start of the integer or expression;
	   if the start point indicates no integer is present,
	   don't try to factor it :) */

	last = strchr(buf, '\n');
	if (last)
		*last = 0;
	int_start = buf;
	while (*int_start && !isdigit(*int_start) &&
			*int_start != '(' ) {
		int_start++;
	}
	if (*int_start == 0)
		return;

	g_curr_factorization = msieve_obj_new(int_start, flags,
					savefile_name, logfile_name,
					nfs_fbfile_name,
					*seed1, *seed2, max_relations,
					nfs_lower, nfs_upper, cpu,
					cache_size1, cache_size2,
					num_threads, mem_mb);
	if (g_curr_factorization == NULL) {
		printf("factoring initialization failed\n");
		return;
	}

	msieve_run(g_curr_factorization);

	if (!(g_curr_factorization->flags & MSIEVE_FLAG_FACTORIZATION_DONE)) {
		printf("\ncurrent factorization was interrupted\n");
		exit(0);
	}

	// Count factors.  If !=2  return error
	factor = g_curr_factorization->factors;
		while (factor != NULL) {
			count++;
			factor = factor->next;
		}
	if (count != 2) {
		fprintf(stderr,"ERROR: !!!  Number of factors %d \n",count);
		exit(0);
	}

	/* If no logging is specified, at least print out the
	   factors that were found */

	if (!(g_curr_factorization->flags & (MSIEVE_FLAG_USE_LOGFILE |
					MSIEVE_FLAG_LOG_TO_STDOUT))) {
		factor = g_curr_factorization->factors;

		fprintf(stderr,"\n");
		fprintf(stderr,"%s\n", buf);
		count=0;
		while (factor != NULL) {
			char *factor_type;

			if (factor->factor_type == MSIEVE_PRIME)
				factor_type = "p";
			else if (factor->factor_type == MSIEVE_COMPOSITE)
				factor_type = "c";
			else
				factor_type = "prp";

			fprintf(stderr,"%s%d: %s\n", factor_type, 
					(int32)strlen(factor->number), 
					factor->number);
			if (count==0) {
        			BN_dec2bn(p, factor->number); 
				count++;
			} else {
        			BN_dec2bn(q, factor->number); 
			}
			factor = factor->next;
		}
		fprintf(stderr,"\n");
	}


	/* free the current factorization struct. The following
	   avoids a race condition in the signal handler */

	obj = g_curr_factorization;
	g_curr_factorization = NULL;
	if (obj)
		msieve_obj_free(obj);
}

int main(int argc, char * argv[]) {
	BIGNUM *n, *c, *dcs, *zero, *exp, *one, *s, *t, *a , *m, *p, *q, *d, *pm1, *qm1, *r,*u;
	BIGNUM *totient;
	int nbits; 
	int is,flag,i,j,bl; 
     	char buffer[1000];
	char num[1000];
	FILE *in ;
	int MB=8;
        BIGNUM * e;
	BN_CTX *ctx;

	char buf[400];
	uint32 seed1, seed2;
	char *savefile_name = NULL;
	char *logfile_name = NULL;
	char *nfs_fbfile_name = NULL;
	uint32 flags;
	uint32 max_relations = 0;
	uint32 cache_size1; 
	uint32 cache_size2; 
	uint32 num_threads = 0;
	uint32 mem_mb = 0;
	uint64 nfs_lower = 0;
	uint64 nfs_upper = 0;
	enum cpu_type cpu;
	msieve_factor *factor;
	int lletra;



	ctx = BN_CTX_new();
        n=BN_new(); e=BN_new(); c=BN_new(); dcs=BN_new(); zero=BN_new(); exp=BN_new();
	one=BN_new(); s=BN_new(); t=BN_new(); a=BN_new(); m=BN_new(); p=BN_new(); q=BN_new(); d=BN_new(); pm1=BN_new(); qm1=BN_new(); d=BN_new(); totient=BN_new(); r=BN_new(); u=BN_new();
        BN_dec2bn(&e, "3"); // Uses  e=3 
        BN_dec2bn(&dcs, "256"); 
        BN_dec2bn(&zero, "0"); 
        BN_dec2bn(&one, "1"); 


	if (argc != 2) {
		printf("Usage:  %s cipher_text_file   \n", argv[0]);
		exit(0);
        }
	BN_dec2bn(&n,argv[2]);


	in = fopen(argv[1],"r"); 
	fscanf(in,"Public key N: %s\n",buffer);
	BN_dec2bn(&n,buffer);
	fscanf(in,"Public key e: %s\n",buffer);
	BN_dec2bn(&e,buffer);
        fclose(in);

	fprintf(stderr,"N:  %s \n",BN_bn2dec(n));
	fprintf(stderr,"e:  %s \n",BN_bn2dec(e));

	// Factoring N
	get_cache_sizes(&cache_size1, &cache_size2);
	cpu = get_cpu_type();
	flags = MSIEVE_FLAG_USE_LOGFILE;

	buf[0] = 0;
	flags &= ~(MSIEVE_FLAG_USE_LOGFILE | MSIEVE_FLAG_LOG_TO_STDOUT);
	strncpy(buf, BN_bn2dec(n), sizeof(buf));

	if (isdigit(buf[0]) || buf[0] == '(' ) {
		factor_integer(buf, flags, savefile_name, 
				logfile_name, nfs_fbfile_name,
				&seed1, &seed2,
				max_relations, 
				nfs_lower, nfs_upper, cpu,
				cache_size1, cache_size2,
				num_threads, mem_mb, &p,&q);
	}
	//  End  factoring


	fprintf(stderr,"P:  %s \n",BN_bn2dec(p));
	fprintf(stderr,"Q:  %s \n",BN_bn2dec(q));

	BN_sub(pm1,p,one);
	BN_sub(qm1,q,one);
	BN_mul(totient,pm1,qm1,ctx);
	BN_mod_inverse(d,e,totient,ctx);
	fprintf(stderr,"d:  %s \n",BN_bn2dec(d));
	fprintf(stderr,"phi(N):  %s \n\n\n",BN_bn2dec(totient));

	in = fopen(argv[1],"r"); 
	while (fgets(buffer,1000,in)){
		if (sscanf(buffer,"Word: %s\n",buf)){
			//printf(">>>%s\n",buf);
			BN_dec2bn(&c,buf);
	  		BN_mod_exp(m,c,d,n,ctx);
			BN_copy(r,m);
	  		BN_copy(exp,zero);
			for (i=0; i<MB; i++){
				BN_exp(t,dcs,exp,ctx);
				BN_div(u,NULL,r,t,ctx);
				BN_mod(a,u,dcs,ctx);
				BN_mul(s, a, t,ctx);
				BN_sub(r,r,s);
				BN_add(exp,exp,one);
		
				lletra=atoi(BN_bn2dec(a));
				printf("%c",lletra);
				
			}
		}
	}
        fclose(in);
	printf("\n\n");


}

