#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <string.h>


unsigned char* key_str = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCHJJ1kxhOXDh4M\n"\
"9QgXj2sXahxG7clGnWDp5YW9f/+Xyf2RzZma1JB76KqXh2ZNyJfpG/4tsUqm1KBQ\n"\
"3w1glvsvUsCcuiAhVmT3CkN7+M/S+ttcXIlNfT+x2UH4h50d1IPLr7qSjgiBkPcW\n"\
"2WFFXxRfaUqSg7xhLp+9ydXJJFQbvTBKCpr2HFRl4DEuF5SxganG8SQau/swCf2l\n"\
"3lHnrIm4ER5B+O4RNqYr/AMo6tge1LXaYp9ss8TM3VmTTGNHGcIaPvSIeBsT4Xol\n"\
"hkZ0RyyT++m1ABSKn1kA8Rv5vjzj5WbHDi8LefreQ3gcBax26h/6tbvgTgMwIDzo\n"\
"kRrUOM39AgMBAAECggEAcpm7GtTZkfP3ybcUKJ6HCvEBj6hfUZFtuIrZccwUW4x/\n"\
"id/WzTRKXbj8yMiaGYXsRFJnpim9C2ItnMa5mloOIaBEE+PGEV8o+VDrzzo8SkZO\n"\
"NLGIAX0fwVpiFjYyJzSqmtSnG1Z0oiLjVa37TY+GQC6SfVJXMfYOoiuBLjOvW2FB\n"\
"8AJQX6G8dU6S4WZc1RdJ9ZyyQgcfKtt/kvja/JroMkOx2SQ13Yd7BU19xFVJCPiE\n"\
"PF9K+CtTIYO/hkHdUwh8+p74QaEHemJ1HfE2bFtZMEplBoSa06zwzUVx0WV1Y3j/\n"\
"qg7rxrDNl6ITmWTyQEn3bdJn0XPrvcRmv4sgce1K4QKBgQDWNyEUlg3yMKJyNmnK\n"\
"8oLUggXNkBC7ayRkN67MsUdS9gsFBhlOZeocrzb+T9GZUpVfDGmLO5708P8eZbRD\n"\
"DNRSVMyr0eV89sPXx579kyV9/nMzA65LasldlNC15gyr61/ldp6Uleb3bUEeYe7A\n"\
"kRnzSrJfLOTLUoTi7huVY59vKQKBgQChgP/FoWD9U/Ahz72IGS3CFFeHZMjFQfry\n"\
"rVBu5aL8iXeTj9ansKeUbIecYW3UqS+HbO6vbx+VvHeG5wlSEbernMNWrny5FQze\n"\
"ichKjbOkXmp50dQVvuebyvPYaIAkB7BFLEXqk0rBn5TPPQFS4bLcXe/xeCkF0Gd+\n"\
"uBrI4IpGtQKBgG1uFjkU+qTZUXL09xBU2J7EmUBMsy966UlE5MfuXBg2VqTHW9Af\n"\
"4furSnWZwuIHPQUkKxqUZ3yLTFhz7iU+fYxdg3zWqdwvlxY5BLBXJhT6ElFiNPyT\n"\
"3bAvoHr7vUdp40AuW45eEXIeXuCteLDorxAI/Zv/LBXt3rKqnm6vSLgZAoGASa7d\n"\
"AoGaCnndOM/anNk/8yfstyzYHIb5wvYnmDDUp3rgP0aEnIUQL7tEM6iPv1JhCNw+\n"\
"GXQNaPdPYRDPQ84pifY/eLCq3pYoBO+/naQAraEV2vZMWI98g6uYjMdAjy+i0Cxe\n"\
"yaLhnGz+K36dt/6Y58lDy1sS/EAUt8+vCK7I53ECgYEAu/Sup6U7CPpNarNbfgNJ\n"\
"GpNtijMWSwuM5cwB/7T1uhiA9pR9pxkjOA2RxopokqmjfhKSNi6MLSfkxayK/x/3\n"\
"3VqJotqMylQns2G9ZlAJ+zUkB/Ihe1eSkP14e3jiFDaYuXwdW8JUUHVXv+dagCdu\n"\
"/aTZdrJg9UmrnYY6qx9F7gc=\n"\
"-----END RSA PRIVATE KEY-----\n";    

RSA*
createRSA(const unsigned char * key, int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (!keybio) {
        printf( "Failed to create key BIO");
        return 0;
    }
    if (public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    
    if(rsa == NULL) {
        printf( "Failed to create RSA");
    }
    
    BIO_free(keybio);
    return rsa;
}

EVP_PKEY*
make_key(RSA *rsa)
{
    EVP_PKEY *pkey = NULL;

    if (!rsa) {
        return pkey;
    }
    
    do {
        pkey = EVP_PKEY_new();
        if (pkey == NULL) {
            printf("EVP_PKEY_new failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        if (rsa == NULL) {
            printf("RSA_generate_key failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_PKEY_assign_RSA(pkey, RSAPrivateKey_dup(rsa));
        if (rc != 1) {
            printf("EVP_PKEY_assign_RSA (1) failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
    } while(0);
        
    return pkey;
}

/* msg: sha-256-digest, mlen: 256 / 8, pkey: RSA Key */
unsigned char*
sign_it_pkcs1(const unsigned char* msg, size_t mlen, size_t* slen, EVP_PKEY* pkey)
{
     EVP_PKEY_CTX *ctx = NULL;
     unsigned char *sig = NULL;
     
     ctx = EVP_PKEY_CTX_new(pkey, NULL);
     if (!ctx) {
         goto end;
     }
     
     if (EVP_PKEY_sign_init(ctx) <= 0) {
         goto end;
     }
 
     if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
         goto end;
     }
 
     if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
         goto end;
     }
 
     if (EVP_PKEY_sign(ctx, NULL, slen, msg, mlen) <= 0) {
         goto end;
     }

     sig = OPENSSL_malloc(*slen);

     if (sig == NULL) {
         goto end;
     }

     if (EVP_PKEY_sign(ctx, sig, slen, msg, mlen) <= 0) {
         OPENSSL_free(sig);
         sig = NULL;
         goto end;
     }

 end:
     if (ctx) {
         EVP_PKEY_CTX_free(ctx);
     }

     return sig;
}

unsigned char*
rsa_sha256_sign(unsigned char *rsa_key, unsigned char *msg, size_t mlen, size_t *slen)
{
    if (!msg || mlen <= 0) {
        return NULL;
    }

    RSA *rsa = NULL;
    EVP_PKEY *skey = NULL;
    unsigned char *sig = NULL;
    
    unsigned char *sha_digest = SHA256((unsigned char*)msg, mlen, NULL);
        
    rsa = createRSA(rsa_key, 0);

    if (!rsa) {
        goto end;
    }

    skey = make_key(rsa);

    if (!skey) {
        goto end;
    }

    sig = sign_it_pkcs1(sha_digest, SHA256_DIGEST_LENGTH, slen, skey);
    
 end:
    if (rsa) {
        RSA_free(rsa);
    }

    if (skey) {
        EVP_PKEY_free(skey);        
    }

    return sig;
}

int
main()
{
    const char* msg = "helloworld";
    size_t siglen;
    
    unsigned char* sig = rsa_sha256_sign(key_str, msg, (size_t)strlen(msg), &siglen);
    if (!sig) {
        printf("cannot sign\n");
        return 0;
    }
    
    printf("%d\n", siglen);     
    for (int i = 0; i < siglen; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");

    if (sig) {
        OPENSSL_free(sig);
    }

    return 0;
}
