/**
 * 3_sign_digest.c
 * ---------------
 * Signed message digests: hash a file with SHA-256, then either
 * encrypt the digest with RSA (public key) or sign it (private key).
 *
 * This mixes raw OpenSSL (for explicit SHA-256 hashing) with common.c
 * wrappers (for RSA operations), so you see both levels.
 *
 * Python equivalent:
 *   hash_function = hashes.Hash(hashes.SHA256())
 *   hash_function.update(file_data)
 *   message_digest_bytes = hash_function.finalize()     → 32 bytes
 *
 *   encrypted = public_key.encrypt(digest, OAEP(...))   → 128 bytes
 *   decrypted = private_key.decrypt(encrypted, OAEP(.)) → 32 bytes
 *
 *   signature = private_key.sign(data, PSS(...), SHA256) → 128 bytes
 *   public_key.verify(signature, data, PSS(...), SHA256) → ok or error
 *
 * Compile: gcc -Wall -O2 -o 3_sign_digest 3_sign_digest.c common.c -lssl -lcrypto
 */

#include "common.h"
#include <openssl/bio.h>
#include <openssl/evp.h>

/* Global RSA key pair:  generated once, used by both functions */
static EVP_PKEY *key_pair = NULL;

/* Base64-encode for display (same helper as Part 1) */
static char *base64_encode(const unsigned char *data, size_t len)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    char *out = malloc(bptr->length + 1);
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';
    BIO_free_all(b64);
    return out;
}

/**
 * TASK 3-2: Compute SHA-256 hash of data.
 * Returns a 32-byte buffer (caller must free).
 */
static unsigned char *compute_sha256(const unsigned char *data, size_t len, unsigned int *digest_len)
{
    unsigned char *digest = malloc(EVP_MAX_MD_SIZE);

    // TODO: Task 3-2

    return digest; /* 32 bytes for SHA-256 */

    /* END OF TASK 3-2 */
}

/**
 * enc_digest: Hash the file, encrypt the digest with the public key,
 * then decrypt it back and verify they match.
 *
 * Demonstrates: public-key encryption of a digest (OAEP padding).
 */
void enc_digest(const char *filename)
{
    /* Read the file */
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        perror(filename);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *file_data = malloc(file_len);
    fread(file_data, 1, file_len, fp);
    fclose(fp);

    /*
     * Task 3-3: Compute SHA-256 hash of the file data.
     *
     * Python:
     *   hash_function = hashes.Hash(hashes.SHA256())
     *   hash_function.update(file_data)
     *   message_digest_bytes = hash_function.finalize()
     */
    // TODO: Task 3-3
    unsigned int digest_len = 0;
    unsigned char *digest = 0; // modify this assignment
    /* END OF TASK 3-3 */

    char *digest_b64 = base64_encode(digest, digest_len);
    printf("Original hash bytes: %s\n", digest_b64);
    printf("Length of hash bytes of %s is %u\n", filename, digest_len);
    free(digest_b64);

    /*
     * Task 3-4: Encrypt the digest with the PUBLIC key (OAEP padding)
     *
     * We use rsa_encrypt_block with use_oaep=1.
     */
    /* Note: in OpenSSL 3.x, we can use the private EVP_PKEY for public operations too,
       but conceptually we're using the public key here. */
    size_t enc_len = 0;
    // TODO: Task 3-4
    unsigned char *encrypted = 0; // modify this assignment
    /* END OF TASK 3-4 */

    char *enc_b64 = base64_encode(encrypted, enc_len);
    printf("Encrypted hash bytes: %s\n", enc_b64);
    free(enc_b64);

    /*
     * Task 3-5: Decrypt the digest back.
     */
    size_t dec_len = 0;
    // TODO: Task 3-5
    unsigned char *decrypted = 0; // modify this assignment
    /* END OF TASK 3-5 */

    char *dec_b64 = base64_encode(decrypted, dec_len);
    printf("Decrypted hash bytes: %s\n", dec_b64);
    free(dec_b64);

    /* Verify the round-trip */
    if (dec_len == digest_len && memcmp(digest, decrypted, digest_len) == 0)
    {
        printf("✓ Digest round-trip OK\n");
    }
    else
    {
        printf("✗ Digest mismatch!\n");
    }
    printf("\n");

    free(file_data);
    free(digest);
    free(encrypted);
    free(decrypted);
}

/**
 * sign_digest: Sign the file data with the private key (PSS padding),
 * then verify the signature with the public key.
 *
 * Note: private_key.sign() in Python hashes internally before signing.
 * Our sign_message_pss() from common.c does the same (SHA-256 + PSS).
 */
void sign_digest(const char *filename)
{
    /* Read the file */
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        perror(filename);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *file_data = malloc(file_len);
    fread(file_data, 1, file_len, fp);
    fclose(fp);

    /*
     * Task 3-6: Sign the data with the private key (RSA-PSS, SHA-256).
     *
     * Note: sign() hashes the data internally so you should pass the raw file_data,
     * not the digest. The library computes SHA-256(file_data) then signs that.
     */
    size_t sig_len = 0;
    // TODO: Task 3-6
    unsigned char *signature = 0; // modify this assignment

    /* END OF TASK 3-6 */

    printf("Original data bytes length: %ld bytes\n", file_len);
    printf("Signed message digest length: %zu bytes\n", sig_len);

    char *sig_b64 = base64_encode(signature, sig_len);
    printf("Signed bytes: %s\n", sig_b64);
    free(sig_b64);

    /*
     * Verify the signature using the public key.
     *
     * We need an X509 cert for verify_message_pss(), but here we generated
     * a bare key pair (no cert). So we use raw OpenSSL EVP_DigestVerify directly.
     * This is what verify_message_pss() does internally.
     */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int ok = 0;

    if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, key_pair) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_MAX) > 0 &&
        EVP_DigestVerifyUpdate(md_ctx, file_data, (size_t)file_len) > 0 &&
        EVP_DigestVerifyFinal(md_ctx, signature, sig_len) == 1)
    {
        ok = 1;
    }
    EVP_MD_CTX_free(md_ctx);

    if (ok)
    {
        printf("======= SIGNATURE VERIFIED =======\n");
    }
    else
    {
        print_ssl_error("verify");
        printf("======= INVALID SIGNATURE =======\n");
    }
    printf("\n");

    free(file_data);
    free(signature);
}

int main(void)
{

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    /*
     * Task 3-1: Generate RSA key pair.
     * In C/OpenSSL, EVP_PKEY holds both private and public key.
     */

    // TODO: Task 3-1

    /* END OF TASK 3-1 */
    EVP_PKEY_CTX_free(ctx);

    if (!key_pair)
    {
        fprintf(stderr, "RSA key generation failed\n");
        return 1;
    }
    printf("RSA-1024 key pair generated.\n\n");

    enc_digest("original_files/shorttext.txt");
    enc_digest("original_files/longtext.txt");
    sign_digest("original_files/shorttext.txt");
    sign_digest("original_files/longtext.txt");

    EVP_PKEY_free(key_pair);
    return 0;
}
