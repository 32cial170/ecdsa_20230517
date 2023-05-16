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

    if (!ctx) {
        fprintf(stderr, "Error: EVP_MD_CTX_new\n");
        goto err;
    }

    // Create an EC key pair
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        fprintf(stderr, "Error: EC_KEY_new_by_curve_name\n");
        goto err;
    }

    if (!EC_KEY_generate_key(eckey)) {
        fprintf(stderr, "Error: EC_KEY_generate_key\n");
        goto err;
    }

    // Create an EVP key pair
    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Error: EVP_PKEY_new\n");
        goto err;
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
        fprintf(stderr, "Error: EVP_PKEY_set1_EC_KEY\n");
        goto err;
    }

    // Sign the message
    sig = static_cast<unsigned char*>(malloc(EVP_PKEY_size(pkey)));
    if (!sig) {
        fprintf(stderr, "Error: malloc\n");
        goto err;
    }

    if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey)) {
        fprintf(stderr, "Error: EVP_DigestSignInit\n");
        goto err;
    }

    if (!EVP_DigestSignUpdate(ctx, msg, msglen)) {
        fprintf(stderr, "Error: EVP_DigestSignUpdate\n");
        goto err;
    }

    if (!EVP_DigestSignFinal(ctx, sig, &siglen)) {
        fprintf(stderr, "Error: EVP_DigestSignFinal\n");
        goto err;
    }

    err:
    if (eckey) EC_KEY_free(eckey);
    if (pkey) EVP_PKEY_free(pkey);
    if (sig) free(sig);
    if (ctx) EVP_MD_CTX_free(ctx);
}
