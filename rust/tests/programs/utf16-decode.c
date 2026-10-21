// a UTF-16LE string, xor-decoded into a zeroed heap buffer.
// FLOSS diffs memory byte by byte, so the zero high bytes of each
// character are "unchanged" and the string is split into single characters.
#include "common.h"

static const wchar encoded[] = {'h' ^ 0x55, 'e' ^ 0x55, 'l' ^ 0x55, 'l' ^ 0x55, 'o' ^ 0x55, ' ' ^ 0x55,
                                'w' ^ 0x55, 'i' ^ 0x55, 'd' ^ 0x55, 'e' ^ 0x55, ' ' ^ 0x55, 'w' ^ 0x55,
                                'o' ^ 0x55, 'r' ^ 0x55, 'l' ^ 0x55, 'd' ^ 0x55, 0x55};

__declspec(noinline) void decode(wchar *out, const wchar *in, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = in[i] ^ 0x55;
    }
}

void main(void) {
    wchar *buf = HeapAlloc(GetProcessHeap(), 8 /* HEAP_ZERO_MEMORY */, 64);
    decode(buf, encoded, sizeof(encoded) / sizeof(encoded[0]));
    OutputDebugStringW(buf);
    ExitProcess(0);
}
