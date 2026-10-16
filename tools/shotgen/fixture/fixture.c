#include <stdio.h>
#include <string.h>

unsigned long long fnv1a(const unsigned char *data, size_t len) {
    unsigned long long h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 1099511628211ULL; }
    return h;
}

size_t count_printable(const unsigned char *data, size_t len) {
    size_t n = 0;
    for (size_t i = 0; i < len; i++) if (data[i] >= 0x20 && data[i] < 0x7f) n++;
    return n;
}

int transform(int x, int mode) {
    switch (mode) {
        case 0: return x ^ 0x5a;
        case 1: return (x << 3) | ((unsigned)x >> 29);
        case 2: return x + 0x1337;
        default: return ~x;
    }
}

int main(int argc, char **argv) {
    unsigned char buf[64];
    for (int i = 0; i < 64; i++) buf[i] = (unsigned char)(transform(i, argc & 3));
    printf("hash: %016llx\n", (unsigned long long)fnv1a(buf, sizeof(buf)));
    printf("printable: %zu\n", count_printable(buf, sizeof(buf)));
    return 0;
}
