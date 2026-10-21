// a string constructed in a global buffer, one character at a time.
// FLOSS only looks for constructed strings on the stack.
#include "common.h"

static char path[32];

__declspec(noinline) void build(void) {
    path[0] = 'C'; path[1] = ':'; path[2] = '\\'; path[3] = 'm'; path[4] = 'a';
    path[5] = 'l'; path[6] = 'w'; path[7] = 'a'; path[8] = 'r'; path[9] = 'e';
    path[10] = '.'; path[11] = 'e'; path[12] = 'x'; path[13] = 'e'; path[14] = 0;
}

void main(void) {
    build();
    OutputDebugStringA(path);
    ExitProcess(0);
}
