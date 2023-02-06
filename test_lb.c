#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "test_lb.h"

/* whether to compare with the default provider */
/*
 * #define COMPARE_WITH_DEFAULT
 */

/* whether to compare with the md5_mb provider */
/*
 * #define COMPARE_WITH_MD5_MB
 */

/* whether to load from config file */
/*
 */
#define LOAD_FROM_CONF_FILE

/* Test case selection:
 *  - #undef to disable the related test cases
 *  - #define to enable the related test cases
 */
#define MULTI_THREAD_TEST
// #define CTX_LIFE_CYCLE_TEST

// #define DEBUG_PRINT printf
#define DEBUG_PRINT
#define ERROR_PRINT printf
#define PRINT_PREFIX "****** "

#define COUNT_REPETITION (10*1)         /* default TEST, and the outer loop of CTX_LIFE_CYCLE_TEST */
#define COUNT_CTX_RESET_LOOPS (100000)  /* inner loop counts of CTX_LIFE_CYCLE_TEST and MULTI_THREAD_TEST */
#define COUNT_THREADS (1000)            /* number of parallel threads for MULTI_THREAD_TEST */
#define MESG_LENGTH (1024)              /* message text length, for CTX_LIFE_CYCLE_TEST and MULTI_THREAD_TEST */

/* calc_md5_ctx_reset - test MD_CTX cycle with EVP_MD_CTX_reset
 * return:
 *   1, failed
 *   0, success
 */
static int calc_md5_ctx_reset(OSSL_LIB_CTX *libctx, char *prop, int loop)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md5 = NULL;
    const unsigned char msg[MESG_LENGTH] = {
        0x00, 0x01, 0x02, 0x03
    };
    unsigned int len = 0;
    unsigned char outdigest[16];
    int ret = 1;

    md5 = EVP_MD_fetch(libctx, "MD5", prop);
    if (md5 == NULL) {
        DEBUG_PRINT("Failed to fetch MD5\n");
        goto err;
    }
    DEBUG_PRINT(PRINT_PREFIX "Success EVP_MD_fetch MD5 from libctx\n");

    /* Use the digests */

    /* Create a context for the digest operation */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Err 1\n");
        goto err;
    }
    for (int i = 0; i < COUNT_CTX_RESET_LOOPS; i++) {
        DEBUG_PRINT(PRINT_PREFIX "Round %d, EVP_MD_CTX Reset Round %d:\n", loop, i);

        /* Initialise the digest operation */
        if (!EVP_DigestInit_ex(ctx, md5, NULL)) {
            DEBUG_PRINT(PRINT_PREFIX "Err 2\n");
            goto err;
        }

        /* print load-balancer result */
        DEBUG_PRINT(PRINT_PREFIX "Using actual implementation, name: %s, description: %s\n",
                EVP_MD_get0_name(EVP_MD_CTX_get0_md(ctx)),
                EVP_MD_get0_description(EVP_MD_CTX_get0_md(ctx)));
        DEBUG_PRINT(PRINT_PREFIX "EVP_MD_get_size()=%d\n", EVP_MD_get_size(EVP_MD_CTX_get0_md(ctx)));

        if (!EVP_DigestUpdate(ctx, msg, sizeof(msg))) {
            DEBUG_PRINT(PRINT_PREFIX "Err 3\n");
            goto err;
        }
#if 0
        if ((i % 3) == 0) {
            DEBUG_PRINT(PRINT_PREFIX PRINT_PREFIX "Transit from DigestUpdate -> DigestInit\n");
            continue;
        }
#endif

        if (!EVP_DigestFinal_ex(ctx, outdigest, &len)) {
            DEBUG_PRINT(PRINT_PREFIX "Err 5\n");
            goto err;
        }

        if ((i % 3) == 1) {
            DEBUG_PRINT(PRINT_PREFIX PRINT_PREFIX "Transit from DigestFinal -> DigestInit\n");
            continue;
        }

        EVP_MD_CTX_reset(ctx);
    } /* end of for */

    ret = 0;

err:
    /* Clean up all the resources we allocated */
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md5);
    if (ret != 0)
       ERR_print_errors_fp(stderr);
    return ret;
}

/*
 * return:
 *   1, failed
 *   0, success
 */
static int calc_md5(OSSL_LIB_CTX *libctx, char *prop)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md5 = NULL;
    const unsigned char msg[] = {
        0x00, 0x01, 0x02, 0x03
    };
    unsigned int len = 0;
    unsigned char *outdigest = NULL;
    int ret = 1;

    md5 = EVP_MD_fetch(libctx, "MD5", prop);
    if (md5 == NULL) {
        DEBUG_PRINT("Failed to fetch MD5\n");
        goto err;
    }

    DEBUG_PRINT(PRINT_PREFIX "Success EVP_MD_fetch MD5 from libctx %p\n", libctx);

    /* Use the digests */

    /* Create a context for the digest operation */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Err 1\n");
        goto err;
    }

    /* Initialise the digest operation */
    if (!EVP_DigestInit_ex(ctx, md5, NULL)) {
        DEBUG_PRINT(PRINT_PREFIX "Err 2\n");
        goto err;
    }

    /* to print md name */
    DEBUG_PRINT(PRINT_PREFIX "Using implementation name: %s, description: %s\n",
           EVP_MD_get0_name(EVP_MD_CTX_get0_md(ctx)),
           EVP_MD_get0_description(EVP_MD_CTX_get0_md(ctx)));
    /* Print the size of md result */
    DEBUG_PRINT(PRINT_PREFIX "EVP_MD_get_size()=%d\n", EVP_MD_get_size(EVP_MD_CTX_get0_md(ctx)));

    /*
     * Pass the message to be digested. This can be passed in over multiple
     * EVP_DigestUpdate calls if necessary
     */
    if (!EVP_DigestUpdate(ctx, msg, sizeof(msg))) {
        DEBUG_PRINT(PRINT_PREFIX "Err 3\n");
        goto err;
    }

    /* Allocate the output buffer */
    outdigest = OPENSSL_malloc(EVP_MD_get_size(EVP_MD_CTX_get0_md(ctx)));
    /* NOTE: cannot use md5, because the real method is fetched is modified by EVP_DigestInit_ex(ctx) */
    if (outdigest == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Err 4\n");
        goto err;
    }

    /* Now calculate the digest itself */
    if (!EVP_DigestFinal_ex(ctx, outdigest, &len)) {
        DEBUG_PRINT(PRINT_PREFIX "Err 5\n");
        goto err;
    }

    /* Print out the digest result */
    BIO_dump_fp(stdout, outdigest, len);

    ret = 0;

err:
    /* Clean up all the resources we allocated */
    OPENSSL_free(outdigest);
    EVP_MD_free(md5);
    EVP_MD_CTX_free(ctx);
    if (ret != 0)
       ERR_print_errors_fp(stderr);
    return ret;
}

/****************************************************************************
 *
 *  multi-thread test
 *
 ****************************************************************************/

typedef struct thread_params {
    OSSL_LIB_CTX *libctx;
    int serial_num;
} THREAD_PARAMS_ST;

static pthread_t thread_ids[COUNT_THREADS];
static THREAD_PARAMS_ST tparams[COUNT_THREADS];

/* thread_entry_func - entry function of a thread
 */
static void *thread_entry_func(void *args)
{
    THREAD_PARAMS_ST *this_param = args;
    OSSL_LIB_CTX *libctx;

    libctx = this_param->libctx;
    if (calc_md5_ctx_reset(libctx,
			   /*
			    * ? is a prefix operator that means that the following
			    * clause is optional but preferred.
			    */
			   "?provider=loadbalance",
                           this_param->serial_num) != 0) {
        DEBUG_PRINT(PRINT_PREFIX "Failed in Thread %d!\n", this_param->serial_num);
    }
    return NULL;
}

/* multi_thread_test_main - entry of multiple threads test case
 *
 * return:
 *   1, failed
 *   0, success
 */
static int multi_thread_test_main(OSSL_LIB_CTX *libctx)
{
    int i, j;
    int ret;
    struct perf start, stop;            /* this implementation */

    /* perf start */
    perf_start(&start);

    /* thread start */
    for (i = 0; i < COUNT_THREADS; i ++) {
        tparams[i].libctx = libctx;
        tparams[i].serial_num = i;
        ret = pthread_create(&thread_ids[i], NULL,
                             &thread_entry_func, (void *)&tparams[i]);
        if (ret != 0) {
            ERROR_PRINT("Thread %d creation failed!\n", i);
            break;
        }
    }

    /* thread join */
    for (j = 0; j < i; j++) {
        pthread_join(thread_ids[j], NULL);
        DEBUG_PRINT(PRINT_PREFIX "Thread %d joined\n", j);
    }

    /* perf stop */
    perf_stop(&stop);

    /* print performance: bandwidth */
    perf_print(stop, start,
               (long long) MESG_LENGTH * COUNT_CTX_RESET_LOOPS * COUNT_THREADS);

    /* return */
    return ret;
}

/* main function */
int main(void)
{
    OSSL_LIB_CTX *parent_libctx = NULL;
    OSSL_PROVIDER *lbprov = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *provmb = NULL;
    int ret = 1;

#ifdef COMPARE_WITH_DEFAULT
    OSSL_PROVIDER *deflt2;
    deflt2 = OSSL_PROVIDER_load(NULL, "default");
    if (deflt2 == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Failed to load Default provider\n");
        goto err;
    }

    if (calc_md5(NULL, NULL) != 0) {
        DEBUG_PRINT(PRINT_PREFIX "Failed to calculate MD5 using the default provider\n");
        goto err;
    }
#endif

#ifdef COMPARE_WITH_MD5_MB
    OSSL_PROVIDER *md5_mb_prov;
    md5_mb_prov = OSSL_PROVIDER_load(NULL, "libmd5mbprov");     /* libmd5mbprov.so */
    if (md5_mb_prov == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Failed to load md5 multi-buffer provider\n");
        goto err;
    }

    if (calc_md5(NULL, "provider=md5mb") != 0) {
        DEBUG_PRINT(PRINT_PREFIX "Failed to calculate MD5 using the multi-buffer provider\n");
        goto err;
    }
    OSSL_PROVIDER_unload(md5_mb_prov);
#else /* COMPARE_WITH_MD5_MB */

    /*
     * Create load-balancing library contexts
     */
    parent_libctx = OSSL_LIB_CTX_new();
    if (parent_libctx == NULL)
        goto err;
    DEBUG_PRINT(PRINT_PREFIX \
           "parent_libctx = %p\n", parent_libctx);

#ifdef LOAD_FROM_CONF_FILE   /* load from config file */
    /*
     * Load config file for the load-balancing library context. We assume that
     * this config file will automatically activate the load-balancing
     * provider and the default provider.
     */
    if (!OSSL_LIB_CTX_load_config(parent_libctx, "openssl-loadbalancing.cnf"))
        goto err;
    DEBUG_PRINT(PRINT_PREFIX \
           "Succeeded to load loadbalance and default providers by config file\n");
#else    /* load explicitly */
    lbprov = OSSL_PROVIDER_load(parent_libctx, "loadbalance");
    if (lbprov == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Failed to load loadbalance provider\n");
        goto err;
    }
    DEBUG_PRINT(PRINT_PREFIX "Succeeded to load loadbalance provider, %p\n", (void *)lbprov);

    deflt = OSSL_PROVIDER_load(parent_libctx, "default");
    if (deflt == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Failed to load Default provider into parent_libctx\n");
        goto err;
    }
    DEBUG_PRINT(PRINT_PREFIX "Succeeded to load default provider, %p\n", (void *)deflt);

    provmb = OSSL_PROVIDER_load(parent_libctx, "libmd5mbprov");
    if (provmb == NULL) {
        DEBUG_PRINT(PRINT_PREFIX "Failed to load libmd5mbprov provider into parent_libctx\n");
        goto err;
    }
    DEBUG_PRINT(PRINT_PREFIX "Succeeded to load libmd5mbprov provider, %p\n", (void *)provmb);
#endif   /* end of load explicitly */

    /* As an example get some digests */

    /*
     * Calculate MD5 for doing the digest. We're
     * using the "parent_libctx" library context here.
     */
#if defined(MULTI_THREAD_TEST)
    ret = multi_thread_test_main(parent_libctx);
    goto err;
#else /* !defined(MULTI_THREAD_TEST) */

    for (int i = 0; i  < COUNT_REPETITION; i++) {
        DEBUG_PRINT(PRINT_PREFIX "Round %d\n", i);
#if !defined(CTX_LIFE_CYCLE_TEST)
        if (calc_md5(parent_libctx, "provider=loadbalance") != 0)
#else /* defined(CTX_LIFE_CYCLE_TEST) */
        if (calc_md5_ctx_reset(parent_libctx, "provider=loadbalance", i) != 0)
#endif
	    {
            DEBUG_PRINT(PRINT_PREFIX "Round %d: Failed to calculate MD5 using the parent_libctx provider\n", i);
            goto err;
        }
    }
    ret = 0;
#endif

#endif /* !defined COMPARE_WITH_MD5_MB */

err:
#ifdef COMPARE_WITH_DEFAULT
    OSSL_PROVIDER_unload(deflt2);
#endif
    OSSL_PROVIDER_unload(lbprov);
    OSSL_PROVIDER_unload(deflt);
    OSSL_PROVIDER_unload(provmb);
    DEBUG_PRINT(PRINT_PREFIX "after unload provmb\n");
    /* Clean up all the resources we allocated */
    OSSL_LIB_CTX_free(parent_libctx);
    DEBUG_PRINT(PRINT_PREFIX "after free parent_libctx\n");
    if (ret != 0)
       ERR_print_errors_fp(stderr);

    return ret;
}
