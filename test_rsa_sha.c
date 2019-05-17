#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <assert.h>

#include <string.h>


const char* key_str = "-----BEGIN RSA PRIVATE KEY-----\n"\
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
 
    return rsa;
}

int
make_key(EVP_PKEY** skey, RSA *rsa)
{
    int result = -1;
    
    if (!skey) {
        return -1;
    }
    
    if (*skey != NULL) {
        EVP_PKEY_free(*skey);
        *skey = NULL;
    }

    if (!rsa) {
        return -1;
    }
    
    do
    {
        *skey = EVP_PKEY_new();
        if(*skey == NULL) {
            printf("EVP_PKEY_new failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        if(rsa == NULL) {
            printf("RSA_generate_key failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_PKEY_assign_RSA(*skey, RSAPrivateKey_dup(rsa));        
        if(rc != 1) {
            printf("EVP_PKEY_assign_RSA (1) failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        result = 0;
        
    } while(0);
        
    return result;
}

/* msg: sha-256-digest, mlen: 256 / 8, pkey: RSA Key */
int
sign_it_pkcs1(const unsigned char* msg, size_t mlen, unsigned char** sig, size_t* slen, EVP_PKEY* pkey)
{
     EVP_PKEY_CTX *ctx;
     
     ctx = EVP_PKEY_CTX_new(pkey, NULL);
     if (!ctx) {
         return -1;
     }
     
     if (EVP_PKEY_sign_init(ctx) <= 0) {
         return -1;
     }
 
     if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
         return -1;
     }
 
     if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
         return -1;
     }
 
     if (EVP_PKEY_sign(ctx, NULL, slen, msg, mlen) <= 0) {
         return -1;
     }

     *sig = OPENSSL_malloc(*slen);

     if (*sig == NULL) {
         return -1;
     }

     if (EVP_PKEY_sign(ctx, *sig, slen, msg, mlen) <= 0) {
         return -1;
     }

     if (ctx) {
         EVP_PKEY_CTX_free(ctx);
         ctx = NULL;
     }

     return 0;
}

int
main()
{
    const char* msg = "helloworld";
    unsigned char *digest = SHA256((unsigned char*)msg, strlen(msg), NULL);
    printf("SHA-256: ");
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }

    printf("\n");
    size_t siglen = 0;
    unsigned char *sig = NULL;
    EVP_PKEY *skey = NULL;
    RSA *rsa = createRSA((unsigned char*)key_str, 0);
    
    if (make_key(&skey, rsa) != 0) {
        exit(1);
    }

    int n;
    n = sign_it_pkcs1(digest, SHA256_DIGEST_LENGTH, &sig, &siglen, skey);
    
    if (n != 0) {
        printf("sign failed %d.", n);
    }

    printf("RSA-SHA256-PKCS1# v1.5: ");
    for (int i = 0; i < siglen; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");
    
    if(rsa) {
        RSA_free(rsa);
        rsa = NULL;
    }

    return 0;
}
