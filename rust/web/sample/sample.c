// a sample for the browser page (web/index.html): strings hidden the ways FLOSS finds them,
// in a freestanding program like those in tests/programs. sample.exe is built by build.sh.
//
//   a registry key, built on the stack a character at a time;
//   a privilege name, xor-decoded in place on the stack;
//   a URL, and a UTF-16 path, xor-decoded by one routine into the heap.
#include "../../tests/programs/common.h"

static const unsigned char url[] = {0x5f, 0x43, 0x43, 0x47, 0x0d, 0x18, 0x18, 0x42, 0x47, 0x53, 0x56, 0x43, 0x52, 0x19, 0x52, 0x4f, 0x56, 0x5a, 0x47, 0x5b, 0x52, 0x19, 0x54, 0x58, 0x5a, 0x18, 0x54, 0x5f, 0x52, 0x54, 0x5c, 0x08, 0x5e, 0x53, 0x0a, 0x12, 0x07, 0x0f, 0x4f, 0x37};
static const wchar path[] = {0x74, 0x0d, 0x6b, 0x67, 0x45, 0x58, 0x50, 0x45, 0x56, 0x5a, 0x73, 0x56, 0x43, 0x56, 0x6b, 0x42, 0x47, 0x53, 0x56, 0x43, 0x52, 0x45, 0x6b, 0x42, 0x47, 0x53, 0x56, 0x43, 0x52, 0x45, 0x19, 0x52, 0x4f, 0x52, 0x37};

// decodes `n` bytes (or UTF-16 characters, with `wide`) xor 0x37.
__declspec(noinline) void *decode(const void *in, int n, int wide) {
    unsigned char *out = HeapAlloc(GetProcessHeap(), 8 /* HEAP_ZERO_MEMORY */, 128);
    for (int i = 0; i < n; i++) {
        if (wide) {
            ((wchar *)out)[i] = ((const wchar *)in)[i] ^ 0x37;
        } else {
            out[i] = ((const unsigned char *)in)[i] ^ 0x37;
        }
    }
    return out;
}

__declspec(noinline) void privilege(void) {
    volatile unsigned char s[] = {0x09, 0x3f, 0x1e, 0x3f, 0x38, 0x2f, 0x3d, 0x0a, 0x28, 0x33, 0x2c, 0x33, 0x36, 0x3f, 0x3d, 0x3f, 0x5a};
    for (int i = 0; i < (int)sizeof(s); i++) {
        s[i] ^= 0x5a;
    }
    OutputDebugStringA((const char *)s);
}

__declspec(noinline) void persistence(void) {
    volatile char s[64];
    s[0] = 'S';
    s[1] = 'o';
    s[2] = 'f';
    s[3] = 't';
    s[4] = 'w';
    s[5] = 'a';
    s[6] = 'r';
    s[7] = 'e';
    s[8] = '\\';
    s[9] = 'M';
    s[10] = 'i';
    s[11] = 'c';
    s[12] = 'r';
    s[13] = 'o';
    s[14] = 's';
    s[15] = 'o';
    s[16] = 'f';
    s[17] = 't';
    s[18] = '\\';
    s[19] = 'W';
    s[20] = 'i';
    s[21] = 'n';
    s[22] = 'd';
    s[23] = 'o';
    s[24] = 'w';
    s[25] = 's';
    s[26] = '\\';
    s[27] = 'C';
    s[28] = 'u';
    s[29] = 'r';
    s[30] = 'r';
    s[31] = 'e';
    s[32] = 'n';
    s[33] = 't';
    s[34] = 'V';
    s[35] = 'e';
    s[36] = 'r';
    s[37] = 's';
    s[38] = 'i';
    s[39] = 'o';
    s[40] = 'n';
    s[41] = '\\';
    s[42] = 'R';
    s[43] = 'u';
    s[44] = 'n';
    s[45] = 0;
    OutputDebugStringA((const char *)s);
}

void main(void) {
    OutputDebugStringA(decode(url, sizeof(url), 0));
    OutputDebugStringW(decode(path, sizeof(path) / sizeof(path[0]), 1));
    privilege();
    persistence();
    ExitProcess(0);
}
