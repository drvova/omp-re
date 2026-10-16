/*
 * Cross-OS test fixture for the rizin integration suites.
 *
 * Compiled per-OS in the cross-os workflow (clang/cc) and pointed at with
 * OMPRE_TEST_BINARY, so the suites run against a binary that has what they look
 * up on Windows and macOS too, where the default `/bin/ls` fixture is absent
 * (Windows) or SIP-protected against the debugger (macOS). Ground truth is
 * still read from rizin at runtime; this only guarantees the shape the setup
 * asserts: a `main` with local variables that calls another function, plus
 * several more functions so the binary has the inter-function gaps the
 * set_flag "free address near main" search and the graph/xref tests expect of
 * a real program.
 *
 * Deliberately trivial, self-contained, and quick to launch under a debugger
 * on a CI runner.
 */
#include <stdio.h>
#include <string.h>

static int accumulate(int a, int b) {
	int sum = a + b;
	return sum;
}

static int square(int x) {
	int r = x * x;
	return r;
}

static int clamp(int v, int lo, int hi) {
	if (v < lo) return lo;
	if (v > hi) return hi;
	return v;
}

static int mix(int a, int b, int c) {
	int x = accumulate(a, b);
	int y = square(c);
	return clamp(x ^ y, 0, 0x7fff);
}

static int fib(int n) {
	int prev = 0, cur = 1;
	for (int i = 0; i < n; i++) {
		int next = prev + cur;
		prev = cur;
		cur = next;
	}
	return cur;
}

static unsigned checksum(const char *s) {
	unsigned h = 5381;
	for (const char *p = s; *p; p++) h = h * 33u + (unsigned char)*p;
	return h;
}

static int transform(int seed) {
	int a = fib(seed & 0xf);
	int b = mix(a, seed, seed + 1);
	return b + square(a);
}

int main(int argc, char **argv) {
	int count = argc;
	const char *name = argv[0];
	int total = accumulate(count, 0x2a);
	total += transform(count);
	total ^= (int)checksum(name);
	printf("omp-re sample fixture: %s total=%d\n", name, total);
	return total & 0xff;
}
