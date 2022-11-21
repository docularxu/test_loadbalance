#include <stdio.h>
#include <unistd.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/* whether to compare with the default provider */
/*
 * #define COMPARE_WITH_DEFAULT
 */

/* whether to load from config file */
/*
 * #define LOAD_FROM_CONF_FILE
 */

#define PRINT_PREFIX "****** "

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
        printf("Failed to fetch MD5\n");
        goto err;
    }

    printf(PRINT_PREFIX "Success EVP_MD_fetch MD5 from libctx\n");

    /* Use the digests */

    /* Create a context for the digest operation */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf(PRINT_PREFIX "Err 1\n");
        goto err;
    }

    /* Initialise the digest operation */
    if (!EVP_DigestInit_ex(ctx, md5, NULL)) {
        printf(PRINT_PREFIX "Err 2\n");
        goto err;
    }

    /*
     * Pass the message to be digested. This can be passed in over multiple
     * EVP_DigestUpdate calls if necessary
     */
    if (!EVP_DigestUpdate(ctx, msg, sizeof(msg))) {
        printf(PRINT_PREFIX "Err 3\n");
        goto err;
    }

    /* Allocate the output buffer */
    printf(PRINT_PREFIX "EVP_MD_get_size()=%d\n", EVP_MD_get_size(EVP_MD_CTX_get0_md(ctx)));
    outdigest = OPENSSL_malloc(EVP_MD_get_size(EVP_MD_CTX_get0_md(ctx)));
    /* NOTE: cannot use md5, because the real method is fetched is modified by EVP_DigestInit_ex(ctx) */
    if (outdigest == NULL) {
        printf(PRINT_PREFIX "Err 4\n");
        goto err;
    }

    /* Now calculate the digest itself */
    if (!EVP_DigestFinal_ex(ctx, outdigest, &len)) {
        printf(PRINT_PREFIX "Err 5\n");
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

int main(void)
{
    OSSL_LIB_CTX *parent_libctx = NULL;
    OSSL_PROVIDER *lbprov = NULL;
    OSSL_PROVIDER *deflt = NULL;
    int ret = 1;

#ifdef COMPARE_WITH_DEFAULT
    OSSL_PROVIDER *deflt2;
    deflt2 = OSSL_PROVIDER_load(NULL, "default");
    if (deflt2 == NULL) {
        printf(PRINT_PREFIX "Failed to load Default provider\n");
        goto err;
    }

    if (calc_md5(NULL, NULL) != 0) {
        printf(PRINT_PREFIX "Failed to calculate MD5 using the default provider\n");
        goto err;
    }
#endif

    /*
     * Create load-balancing library contexts
     */
    parent_libctx = OSSL_LIB_CTX_new();
    if (parent_libctx == NULL)
        goto err;

#ifdef LOAD_FROM_CONF_FILE   /* load from config file */
    /*
     * Load config file for the load-balancing library context. We assume that
     * this config file will automatically activate the load-balancing
     * provider and the default provider.
     */
    if (!OSSL_LIB_CTX_load_config(parent_libctx, "openssl-loadbalancing.cnf"))
        goto err;
    printf(PRINT_PREFIX \
           "Succeeded to load loadbalance and default providers by config file\n");
#else    /* load explicitly */
    lbprov = OSSL_PROVIDER_load(parent_libctx, "loadbalance");
    if (lbprov == NULL) {
        printf(PRINT_PREFIX "Failed to load loadbalance provider\n");
        goto err;
    }
    printf(PRINT_PREFIX "Succeeded to load loadbalance provider, %p\n", (void *)lbprov);

    deflt = OSSL_PROVIDER_load(parent_libctx, "default");
    if (deflt == NULL) {
        printf(PRINT_PREFIX "Failed to load Default provider into parent_libctx\n");
        goto err;
    }
    printf(PRINT_PREFIX "Succeeded to load default provider, %p\n", (void *)deflt);
#endif

    /* As an example get some digests */

    /*
     * Calculate MD5 for doing the digest. We're
     * using the "parent_libctx" library context here.
     */
    if (calc_md5(parent_libctx, "provider=loadbalance") != 0) {
        printf(PRINT_PREFIX "Round 1: Failed to calculate MD5 using the parent_libctx provider\n");
        goto err;
    }
    if (calc_md5(parent_libctx, "provider=loadbalance") != 0) {
        printf(PRINT_PREFIX "Round 2: Failed to calculate MD5 using the parent_libctx provider\n");
        goto err;
    }
    ret = 0;

err:
#ifdef COMPARE_WITH_DEFAULT
    OSSL_PROVIDER_unload(deflt2);
#endif
    OSSL_PROVIDER_unload(lbprov);
    OSSL_PROVIDER_unload(deflt);
    /* Clean up all the resources we allocated */
    OSSL_LIB_CTX_free(parent_libctx);
    if (ret != 0)
       ERR_print_errors_fp(stderr);
    return ret;
}
