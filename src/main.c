/*
 * mikebom-cmake-demo — tiny C program that exercises enough of zlib's
 * public API to drive both static-linking AND mikebom's
 * symbol-fingerprint matcher (which looks for at least 8 of zlib's 10
 * well-known public symbols in the binary's exported-symbol table).
 *
 * Pipeline:
 *   1. crc32 + adler32 over the input string.
 *   2. compress() convenience wrapper into a buffer.
 *   3. uncompress() convenience wrapper to round-trip.
 *   4. Manual deflate stream (deflateInit_ / deflate / deflateEnd).
 *   5. Manual inflate stream (inflateInit_ / inflate / inflateEnd).
 *
 * All 10 of mikebom's zlib fingerprint symbols get pulled into the
 * binary's symbol table by the static linker because each is
 * referenced from main().
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <zlib.h>

int main(void) {
    const char *msg = "hello mikebom — cmake + ninja demo";
    const size_t msg_len = strlen(msg);

    /* 1. Lightweight checksums. */
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)msg, (uInt)msg_len);
    uLong adler = adler32(0L, Z_NULL, 0);
    adler = adler32(adler, (const Bytef *)msg, (uInt)msg_len);

    printf("zlib version:  %s\n", zlibVersion());
    printf("crc32:         0x%08lx\n", (unsigned long)crc);
    printf("adler32:       0x%08lx\n", (unsigned long)adler);

    /* 2. compress() convenience wrapper. */
    uLong cmp_cap = compressBound((uLong)msg_len);
    Bytef *cmp_buf = (Bytef *)malloc(cmp_cap);
    uLong cmp_len = cmp_cap;
    int rc = compress(cmp_buf, &cmp_len, (const Bytef *)msg, (uLong)msg_len);
    if (rc != Z_OK) {
        fprintf(stderr, "compress: %d\n", rc);
        free(cmp_buf);
        return 1;
    }
    printf("compress():    %lu -> %lu bytes\n", (unsigned long)msg_len, (unsigned long)cmp_len);

    /* 3. uncompress() round-trip. */
    uLong out_cap = msg_len + 1;
    Bytef *out_buf = (Bytef *)malloc(out_cap);
    uLong out_len = out_cap;
    rc = uncompress(out_buf, &out_len, cmp_buf, cmp_len);
    if (rc != Z_OK || out_len != msg_len || memcmp(out_buf, msg, msg_len) != 0) {
        fprintf(stderr, "uncompress: %d\n", rc);
        free(cmp_buf);
        free(out_buf);
        return 1;
    }
    printf("uncompress():  %lu bytes match input\n", (unsigned long)out_len);

    /* 4. Manual deflate stream — drags in deflateInit_/deflate/deflateEnd. */
    z_stream dstream = {0};
    if (deflateInit(&dstream, Z_BEST_COMPRESSION) != Z_OK) {
        fprintf(stderr, "deflateInit failed\n");
        free(cmp_buf);
        free(out_buf);
        return 1;
    }
    dstream.next_in = (Bytef *)msg;
    dstream.avail_in = (uInt)msg_len;
    dstream.next_out = cmp_buf;
    dstream.avail_out = (uInt)cmp_cap;
    (void)deflate(&dstream, Z_FINISH);
    uLong dlen = cmp_cap - dstream.avail_out;
    (void)deflateEnd(&dstream);
    printf("deflate stream: %lu bytes out\n", (unsigned long)dlen);

    /* 5. Manual inflate stream — drags in inflateInit_/inflate/inflateEnd. */
    z_stream istream = {0};
    if (inflateInit(&istream) != Z_OK) {
        fprintf(stderr, "inflateInit failed\n");
        free(cmp_buf);
        free(out_buf);
        return 1;
    }
    istream.next_in = cmp_buf;
    istream.avail_in = (uInt)dlen;
    istream.next_out = out_buf;
    istream.avail_out = (uInt)out_cap;
    (void)inflate(&istream, Z_FINISH);
    uLong ilen = out_cap - istream.avail_out;
    (void)inflateEnd(&istream);
    printf("inflate stream: %lu bytes back\n", (unsigned long)ilen);

    free(cmp_buf);
    free(out_buf);
    return 0;
}
