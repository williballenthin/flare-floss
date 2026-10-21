// freestanding test programs: no C runtime, a few imports from kernel32.
typedef unsigned short wchar;
__declspec(dllimport) void __stdcall OutputDebugStringA(const char *s);
__declspec(dllimport) void __stdcall OutputDebugStringW(const wchar *s);
__declspec(dllimport) void *__stdcall GetProcessHeap(void);
__declspec(dllimport) void *__stdcall HeapAlloc(void *heap, unsigned long flags, unsigned long size);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);
