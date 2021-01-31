#include <string.h>
#include <windows.h>

#define RtlGenRandom SystemFunction036

BOOLEAN NTAPI
RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#pragma comment(lib, "advapi32.lib")

void drbg_entropy(void *buf, rsize_t bytes) {
    RtlGenRandom((PVOID) buf, (ULONG) bytes);
}
