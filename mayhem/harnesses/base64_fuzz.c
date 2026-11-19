/* Wide-char base64 codec (Sandboxie/common/base64.c), used on Certificate.dat
 * signature blobs: size, decode, then re-encode the result. */
#include <stdint.h>
#include <stdlib.h>
#include "fuzz_wstr.h"
size_t b64_encoded_size(size_t inlen);
int b64_encode(const unsigned char *in, size_t inlen, wchar_t *out, size_t outlen);
size_t b64_decoded_size(const wchar_t *in);
int b64_decode(const wchar_t *in, unsigned char *out, size_t outlen);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wchar_t *in = fuzz_wstr(data, size);
    size_t n, en;
    unsigned char *out;
    if (!in) return 0;
    n = b64_decoded_size(in);
    out = (unsigned char *)malloc(n ? n : 1);
    if (out && b64_decode(in, out, n)) {
        en = b64_encoded_size(n);
        wchar_t *enc = (wchar_t *)malloc((en + 1) * sizeof(wchar_t));
        if (enc) {
            b64_encode(out, n, enc, en);
            free(enc);
        }
    }
    free(out);
    free(in);
    return 0;
}
