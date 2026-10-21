// a decoding loop inlined into the entry point, writing to a global buffer.
// nothing calls the entry point, so FLOSS never emulates it as a decoding routine,
// and its tight string extraction only looks at the stack.
#include "common.h"

static const unsigned char encoded[] = {
    'h' ^ 0x42, 't' ^ 0x42, 't' ^ 0x42, 'p' ^ 0x42, ':' ^ 0x42, '/' ^ 0x42, '/' ^ 0x42, 'e' ^ 0x42,
    'v' ^ 0x42, 'i' ^ 0x42, 'l' ^ 0x42, '.' ^ 0x42, 'e' ^ 0x42, 'x' ^ 0x42, 'a' ^ 0x42, 'm' ^ 0x42,
    'p' ^ 0x42, 'l' ^ 0x42, 'e' ^ 0x42, 0x42};
static char url[sizeof(encoded)];

void main(void) {
    for (unsigned int i = 0; i < sizeof(encoded); i++) {
        url[i] = encoded[i] ^ 0x42;
    }
    OutputDebugStringA(url);
    ExitProcess(0);
}
