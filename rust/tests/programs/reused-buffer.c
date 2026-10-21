// a string decoded, without a terminator, in front of bytes that the caller wrote earlier,
// from two call sites with different leftovers: "secret key-xyz" and "secret key+abc".
// the decoder decoded the same thing both times, so it's reported once, not once per call.
#include "common.h"

static char buf[32];
static const char encoded[] = {'s' ^ 0x55, 'e' ^ 0x55, 'c' ^ 0x55, 'r' ^ 0x55, 'e' ^ 0x55,
                               't' ^ 0x55, ' ' ^ 0x55, 'k' ^ 0x55, 'e' ^ 0x55, 'y' ^ 0x55};

__declspec(noinline) void decode(char *out, const char *in, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = in[i] ^ 0x55;
    }
}

void main(void) {
    buf[10] = '-';
    buf[11] = 'x';
    buf[12] = 'y';
    buf[13] = 'z';
    decode(buf, encoded, sizeof(encoded));
    OutputDebugStringA(buf);

    buf[10] = '+';
    buf[11] = 'a';
    buf[12] = 'b';
    buf[13] = 'c';
    decode(buf, encoded, sizeof(encoded));
    OutputDebugStringA(buf);
    ExitProcess(0);
}
