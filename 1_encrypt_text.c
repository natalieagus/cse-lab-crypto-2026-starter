/**
 * 1_encrypt_text.c
 * ----------------
 * Symmetric key encryption/decryption of text files.
 *
 * We use session_encrypt()/session_decrypt() from common.c which does AES-128-CBC + HMAC-SHA256.
 *
 * Compile: gcc -Wall -O2 -o 1_encrypt_text 1_encrypt_text.c common.c -lssl -lcrypto
 */

#include "common.h"
#include <openssl/bio.h>
#include <openssl/evp.h>

/* Global symmetric key — shared between encrypt and decrypt, just like the Python version */
static unsigned char symmetric_key[SESSION_KEY_LEN];

/**
 * Base64-encode a buffer. Returns a malloc'd null-terminated string.
 * Equivalent to Python's base64.b64encode(data).decode("utf8")
 */
static char *base64_encode(const unsigned char *data, size_t len, size_t *out_len)
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
    if (out_len)
        *out_len = bptr->length;
    BIO_free_all(b64);
    return out;
}

/**
 * Base64-decode a null-terminated string. Returns a malloc'd buffer.
 * Equivalent to Python's base64.b64decode(text.encode("utf8"))
 */
static unsigned char *base64_decode(const char *text, size_t text_len, size_t *out_len)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(text, (int)text_len);
    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);

    unsigned char *out = malloc(text_len); /* decoded is always shorter */
    int n = BIO_read(mem, out, (int)text_len);
    if (out_len)
        *out_len = (size_t)n;
    BIO_free_all(mem);
    return out;
}

/**
 * Encrypt a text file and save the base64-encoded ciphertext.
 */
void enc_text(const char *input_filename, const char *output_filename)
{
    /* Read the plaintext file */
    FILE *fp = fopen(input_filename, "rb");
    if (!fp)
    {
        perror(input_filename);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long raw_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *raw_bytes = malloc(raw_len);
    fread(raw_bytes, 1, raw_len, fp);
    fclose(fp);

    /* TASK 1-2: encrypt text */
    /* Encrypt using session_encrypt (AES-128-CBC + HMAC) */

    size_t encrypted_len = 0;

    // TODO: Task 1-2
    unsigned char *encrypted_bytes = 0; // modify this assignment

    /* END OF TASK 1-2 */

    /* Base64-encode for printable output */
    size_t b64_len = 0;
    char *encrypted_text = base64_encode(encrypted_bytes, encrypted_len, &b64_len);

    /* Save to file */
    FILE *out = fopen(output_filename, "w");
    if (out)
    {
        fwrite(encrypted_text, 1, b64_len, out);
        fclose(out);
    }

    printf("Original byte length: %ld\n", raw_len);
    printf("Encrypted byte length: %zu\n", encrypted_len);
    printf("\n");

    free(raw_bytes);
    free(encrypted_bytes);
    free(encrypted_text);
}

/**
 * Decrypt a base64-encoded ciphertext file and save the plaintext.
 *
 * Python equivalent:
 *   encrypted_bytes = base64.b64decode(encrypted_text.encode("utf8"))
 *   decrypted_bytes = cipher.decrypt(encrypted_bytes)
 */
void dec_text(const char *input_filename, const char *output_filename)
{
    /* Read the base64-encoded ciphertext */
    FILE *fp = fopen(input_filename, "r");
    if (!fp)
    {
        perror(input_filename);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long text_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *encrypted_text = malloc(text_len + 1);
    fread(encrypted_text, 1, text_len, fp);
    encrypted_text[text_len] = '\0';
    fclose(fp);

    /* Base64-decode back to raw ciphertext bytes */
    size_t encrypted_len = 0;
    unsigned char *encrypted_bytes = base64_decode(encrypted_text, (size_t)text_len, &encrypted_len);

    /* TASK 1-3: Decrypt the text */
    /* Decrypt using session_decrypt (verifies HMAC, then AES-CBC) */
    size_t decrypted_len = 0;

    // TODO: Task 1-3
    unsigned char *decrypted_bytes = 0; // modify this assignment

    /* END OF TASK 1-3 */

    if (!decrypted_bytes)
    {
        fprintf(stderr, "Decryption failed (HMAC verification error)\n");
    }
    else
    {
        /* Save the decrypted plaintext */
        FILE *out = fopen(output_filename, "w");
        if (out)
        {
            fwrite(decrypted_bytes, 1, decrypted_len, out);
            fclose(out);
        }

        printf("Encrypted byte length: %zu\n", encrypted_len);
        printf("Decrypted byte length: %zu\n", decrypted_len);
        printf("\n");
        free(decrypted_bytes);
    }

    free(encrypted_text);
    free(encrypted_bytes);
}

int main(void)
{
    /* Task 1-1: Generate a symmetric key */
    memset(symmetric_key, '\0', SESSION_KEY_LEN);

    // TODO: Task 1-1

    /* END OF TASK 1-1 */

    printf("Sym key generated: %s\n\n", (const char *)symmetric_key);
    /* Ensure output directory exists */
    mkdir("output", 0755);

    enc_text("original_files/shorttext.txt", "output/enc_shorttext.txt");
    dec_text("output/enc_shorttext.txt", "output/dec_shorttext.txt");

    enc_text("original_files/longtext.txt", "output/enc_longtext.txt");
    dec_text("output/enc_longtext.txt", "output/dec_longtext.txt");

    return 0;
}
