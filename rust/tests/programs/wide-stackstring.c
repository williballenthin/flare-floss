// a UTF-16 stack string, built with 64-bit and 32-bit stores (as compilers do).
#include "common.h"

void main(void) {
    volatile wchar s[16];
    s[0] = 'k'; s[1] = 'e'; s[2] = 'r'; s[3] = 'n'; s[4] = 'e'; s[5] = 'l';
    s[6] = '3'; s[7] = '2'; s[8] = '.'; s[9] = 'd'; s[10] = 'l'; s[11] = 'l'; s[12] = 0;
    OutputDebugStringW((const wchar *)s);
    ExitProcess(0);
}
