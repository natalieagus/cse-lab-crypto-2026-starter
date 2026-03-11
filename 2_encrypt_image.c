/**
 * 2_encrypt_image.c
 * -----------------
 * Encrypt a BMP image column-by-column using 3DES in ECB or CBC mode.
 *
 * Unlike Part 1 and Part 3, we use raw OpenSSL EVP calls here because
 * common.c doesn't have 3DES or ECB mode. This lets you see the
 * OpenSSL cipher API directly before PA2 wraps it all up.
 *
 * Relevant raw OpenSSL functions:
 *   EVP_EncryptInit_ex(ctx, EVP_des_ede_ecb(), NULL, key, NULL)
 *   EVP_CIPHER_CTX_set_padding(ctx, 0)   // we pad manually with PKCS7
 *   EVP_EncryptUpdate(ctx, out, &len, padded_data, padded_len)
 *   EVP_EncryptFinal_ex(ctx, out + len, &final_len)
 *
 * Compile: gcc -Wall -O2 -o 2_encrypt_image 2_encrypt_image.c common.c -lssl -lcrypto
 */

#include "common.h"

/* ======================================================================
 * BMP structures (24-bit uncompressed only)
 * ====================================================================== */

#pragma pack(push, 1)
typedef struct
{
    uint16_t type; /* "BM" = 0x4D42 */
    uint32_t file_size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t offset; /* offset to pixel data */
} BMPFileHeader;

typedef struct
{
    uint32_t header_size; /* 40 for BITMAPINFOHEADER */
    int32_t width;
    int32_t height; /* positive = bottom-up, negative = top-down */
    uint16_t planes;
    uint16_t bpp; /* bits per pixel, expect 24 */
    uint32_t compression;
    uint32_t image_size;
    int32_t x_ppm;
    int32_t y_ppm;
    uint32_t colors_used;
    uint32_t colors_important;
} BMPInfoHeader;
#pragma pack(pop)

/* ======================================================================
 * PKCS7 padding for 64-bit (8-byte) blocks
 *
 * Appends N bytes each with value N, where N = 8 - (len % 8).
 * If len is already a multiple of 8, appends a full block of 0x08 bytes.
 * ======================================================================
 */

static unsigned char *pkcs7_pad(const unsigned char *data, size_t len, size_t *padded_len)
{
    unsigned char *out = malloc(*padded_len);
    /*  TASK 2-2: Implement pkcs7 padding */

    // TODO: Task 2-2

    /* END OF TASK 2-2 */
    return out;
}

/* ======================================================================
 * 3DES encrypt a single buffer (one column's worth of padded bytes)
 * ======================================================================
 */

static unsigned char *des3_encrypt(const unsigned char *key,
                                   const unsigned char *iv, /* NULL for ECB */
                                   int use_cbc,
                                   const unsigned char *data, size_t data_len,
                                   size_t *out_len)
{
    /**
     * Raw OpenSSL EVP cipher API
     * this is what common.c's session_encrypt hides from you. Here you see every step.
     *
     * EVP_des_ede_ecb() = 3DES in ECB mode (8-byte key used 3 times)
     * EVP_des_ede_cbc() = 3DES in CBC mode (requires an IV)
     */
    const EVP_CIPHER *cipher = use_cbc ? EVP_des_ede_cbc() : EVP_des_ede_ecb();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    /* We already padded manually with PKCS7, so disable OpenSSL's auto-padding */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

    unsigned char *out = malloc(data_len + 8); /* at most one extra block */
    int len = 0, final_len = 0;

    EVP_EncryptUpdate(ctx, out, &len, data, (int)data_len);
    EVP_EncryptFinal_ex(ctx, out + len, &final_len);
    *out_len = (size_t)(len + final_len);

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

/* ======================================================================
 * Image encryption — column by column
 * ======================================================================
 */

void enc_img(const char *input_filename, const char *output_filename,
             int use_cbc, int top_down)
{
    /* 3DES key and IV */
    const unsigned char key[8] = {0xb6, 0x11, 0xd5, 0xd7, 0x83, 0xb2, 0x2c, 0x6d};
    const unsigned char iv[8] = {0x94, 0x6b, 0xae, 0x83, 0x40, 0x44, 0xfc, 0x63};

    /* Read the BMP file */
    FILE *fp = fopen(input_filename, "rb");
    if (!fp)
    {
        perror(input_filename);
        return;
    }

    BMPFileHeader fhdr;
    BMPInfoHeader ihdr;
    fread(&fhdr, sizeof(fhdr), 1, fp);
    fread(&ihdr, sizeof(ihdr), 1, fp);

    if (fhdr.type != 0x4D42 || ihdr.bpp != 24)
    {
        fprintf(stderr, "%s: Only 24-bit uncompressed BMP supported.\n", input_filename);
        fclose(fp);
        return;
    }

    int width = ihdr.width;
    int height = abs(ihdr.height);
    int bmp_bottom_up = (ihdr.height > 0); /* BMP default is bottom-up */

    /* Row stride: each row padded to 4-byte boundary */
    int row_stride = ((width * 3) + 3) & ~3;

    /* Read all pixel data */
    fseek(fp, fhdr.offset, SEEK_SET);
    unsigned char *pixels = malloc(row_stride * height);
    fread(pixels, 1, row_stride * height, fp);
    fclose(fp);

/* Helper: get pixel (r,g,b) at (col, row) accounting for BMP orientation */
#define GET_PIXEL(col, row) (pixels + (bmp_bottom_up ? (height - 1 - (row)) : (row)) * row_stride + (col) * 3)

    /* Allocate output pixel buffer (same size) */
    unsigned char *out_pixels = malloc(row_stride * height);
    memcpy(out_pixels, pixels, row_stride * height); /* copy padding bytes */

    /* Process each column */
    for (int c = 0; c < width; c++)
    {
        /*
         * Extract column bytes -- 3 bytes per pixel, height pixels per column.
         *
         * top_down: iterate row 0 → height-1 (top of image first)
         * bottom_up: iterate row height-1 → 0 (bottom of image first)
         */
        size_t col_len = (size_t)(height * 3);
        unsigned char *col_bytes = malloc(col_len);

        for (int r = 0; r < height; r++)
        {
            int src_row = top_down ? r : (height - 1 - r);
            unsigned char *px = GET_PIXEL(c, src_row);
            col_bytes[r * 3 + 0] = px[0]; /* R (or B depending on BMP) */
            col_bytes[r * 3 + 1] = px[1]; /* G */
            col_bytes[r * 3 + 2] = px[2]; /* B (or R) */
        }

        /*
         * Pad with PKCS7 to 8-byte (64-bit) block boundary.
         */
        size_t padded_len = 0;
        unsigned char *padded = pkcs7_pad(col_bytes, col_len, &padded_len);

        /*
         * TASK 2-3: Encrypt with 3DES (ECB or CBC).
         */
        size_t enc_len = 0;

        // TODO: Task 2-3

        unsigned char *encrypted = 0; // modify this assignment

        /* END OF TASK 2-3 */

        /* Write encrypted bytes back as pixel values (wrapping with modulo 256) */
        for (int r = 0; r < height; r++)
        {
            int dst_row = top_down ? r : (height - 1 - r);
            unsigned char *px = out_pixels + (bmp_bottom_up ? (height - 1 - dst_row) : dst_row) * row_stride + c * 3;
            size_t idx = (size_t)r * 3;
            if (idx + 2 < enc_len)
            {
                px[0] = encrypted[idx + 0];
                px[1] = encrypted[idx + 1];
                px[2] = encrypted[idx + 2];
            }
        }

        free(col_bytes);
        free(padded);
        free(encrypted);
    }

    /* Write output BMP */
    FILE *out = fopen(output_filename, "wb");
    if (out)
    {
        fwrite(&fhdr, sizeof(fhdr), 1, out);
        fwrite(&ihdr, sizeof(ihdr), 1, out);
        /* Write any gap between headers and pixel data */
        size_t header_total = sizeof(fhdr) + sizeof(ihdr);
        if (fhdr.offset > header_total)
        {
            unsigned char *gap = calloc(1, fhdr.offset - header_total);
            fwrite(gap, 1, fhdr.offset - header_total, out);
            free(gap);
        }
        fwrite(out_pixels, 1, row_stride * height, out);
        fclose(out);
    }

    free(pixels);
    free(out_pixels);
    printf("Encrypted %s → %s (%s, %s)\n", input_filename, output_filename,
           use_cbc ? "CBC" : "ECB", top_down ? "top-down" : "bottom-up");
}

int main(void)
{
    mkdir("output", 0755);

    /* SUTD — ECB */
    enc_img("original_files/SUTD.bmp", "output/enc_bottom_up_ecb_SUTD.bmp", 0, 0);
    enc_img("original_files/SUTD.bmp", "output/enc_top_down_ecb_SUTD.bmp", 0, 1);
    /* SUTD — CBC */
    enc_img("original_files/SUTD.bmp", "output/enc_bottom_up_cbc_SUTD.bmp", 1, 0);
    enc_img("original_files/SUTD.bmp", "output/enc_top_down_cbc_SUTD.bmp", 1, 1);

    /* triangle — ECB */
    enc_img("original_files/triangles.bmp", "output/enc_bottom_up_ecb_triangles.bmp", 0, 0);
    enc_img("original_files/triangles.bmp", "output/enc_top_down_ecb_triangles.bmp", 0, 1);
    /* triangle — CBC */
    enc_img("original_files/triangles.bmp", "output/enc_bottom_up_cbc_triangles.bmp", 1, 0);
    enc_img("original_files/triangles.bmp", "output/enc_top_down_cbc_triangles.bmp", 1, 1);

    return 0;
}
