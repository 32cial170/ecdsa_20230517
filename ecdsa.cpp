#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <cstring>

int main()
{
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    const unsigned char *msg = (const unsigned char *)"Hello, world!";
    size_t msglen = strlen((const char *)msg);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    //EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    
    
    if (!ctx || !ctx2) {
        fprintf(stderr, "Error: EVP_MD_CTX_new\n");
        goto err;
}

    // Create an EC key pair
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        fprintf(stderr, "Error: EC_KEY_new_by_curve_name\n");
        goto err;
    }//else printf("1 ok \n");
    if (!EC_KEY_generate_key(eckey)) {
        fprintf(stderr, "Error: EC_KEY_generate_key\n");
        goto err;
    }//else printf("2 ok \n");

    // Create an EVP key pair
    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Error: EVP_PKEY_new\n");
        goto err;
    }//else printf("3 ok \n");
    if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
        fprintf(stderr, "Error: EVP_PKEY_set1_EC_KEY\n");
        goto err;
    }//else printf("4 ok \n");

    // Sign the message

    //sig = malloc(EVP_PKEY_size(pkey));
    sig = static_cast<unsigned char*>(malloc(EVP_PKEY_size(pkey)));

    if (!sig) {
        fprintf(stderr, "Error: malloc\n");
        goto err;
    }//else printf("5 ok \n");
    if (!EVP_DigestSignInit(ctx, &ctx2, md, NULL, pkey)) {
        fprintf(stderr, "Error: EVP_DigestSignInit\n");
        goto err;
    }//else printf("6 ok \n");
    if (!EVP_DigestSignUpdate(ctx2, msg, msglen)) {
        fprintf(stderr, "Error: EVP_DigestSignUpdate\n");
        goto err;
    }//else printf("7 ok \n");
    if (!EVP_DigestSignFinal(ctx2, sig, &siglen)) {
        fprintf(stderr, "Error: EVP_DigestSignFinal\n");
        goto err;
    }//else printf("8 ok \n");

err:
    if (eckey) EC_KEY_free(eckey);
    if (pkey) EVP_PKEY_free(pkey);
    if (sig) free(sig);
    if (ctx) EVP_MD_CTX_free(ctx);
    if (ctx2) EVP_MD_CTX_free(ctx2);
}
