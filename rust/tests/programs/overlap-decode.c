// decode in place, where some ciphertext bytes equal the plaintext.
// FLOSS only extracts strings from bytes that changed, so it reports fragments.
#include "common.h"

// "secret password" with a substitution that leaves 'e', 's', and ' ' alone.
static char data[] = "sxcrxt passwyrd";

__declspec(noinline) void decode(char *s) {
    for (; *s; s++) {
        if (*s == 'x') *s = 'e';
        else if (*s == 'y') *s = 'o';
    }
}

void main(void) {
    decode(data);
    OutputDebugStringA(data);
    ExitProcess(0);
}
