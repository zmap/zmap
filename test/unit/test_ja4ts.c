#define JA4TS_UNIT_TEST 1
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "probe_modules/module_tcp_synscan.h"
#include "probe_modules/module_tcp_synscan.c"

static int failures = 0;

static void expect_eq_str(const char *expected, const char *actual,
			  const char *label)
{
	if (strcmp(actual, expected) != 0) {
		fprintf(stderr, "FAIL %s: expected \"%s\", got \"%s\"\n",
			label, expected, actual);
		failures++;
	} else {
		fprintf(stdout, "PASS %s\n", label);
	}
}

static void test_no_options(void)
{
	char out[256];
	compute_ja4ts(NULL, 0, 64240, out, sizeof(out));
	expect_eq_str("64240__00_00", out, "no_options");
}

static void test_mss_only(void)
{
	uint8_t opts[] = {0x02, 0x04, 0x05, 0xb4};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 65535, out, sizeof(out));
	expect_eq_str("65535_2_1460_00", out, "mss_only");
}

static void test_linux_like(void)
{
	uint8_t opts[] = {
		0x02, 0x04, 0x05, 0xb4,           /* MSS 1460 */
		0x04, 0x02,                       /* SACK-perm */
		0x08, 0x0a, 0,0,0,0, 0,0,0,0,     /* Timestamps */
		0x01,                             /* NOP */
		0x03, 0x03, 0x07,                 /* WScale 7 */
	};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 65535, out, sizeof(out));
	expect_eq_str("65535_2-4-8-1-3_1460_7", out, "linux_like");
}

static void test_wscale_zero(void)
{
	uint8_t opts[] = {0x03, 0x03, 0x00};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 8192, out, sizeof(out));
	expect_eq_str("8192_3_00_0", out, "wscale_zero");
}

static void test_malformed_length(void)
{
	uint8_t opts[] = {
		0x01,             /* NOP */
		0x02, 99,         /* MSS with bogus length */
		0x02, 0x04, 0x05, 0xb4,
	};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 1000, out, sizeof(out));
	expect_eq_str("1000_1-2_00_00", out, "malformed_length");
}

static void test_eol_stops(void)
{
	uint8_t opts[] = {
		0x02, 0x04, 0x05, 0xb4,
		0x00,                   /* EOL */
		0x03, 0x03, 0x07,       /* not reached */
	};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 64240, out, sizeof(out));
	/* EOL kind (0) appears in kinds list because the kind is recorded before the EOL break. */
	expect_eq_str("64240_2-0_1460_00", out, "eol_stops");
}

int main(void)
{
	test_no_options();
	test_mss_only();
	test_linux_like();
	test_wscale_zero();
	test_malformed_length();
	test_eol_stops();

	return failures == 0 ? 0 : 1;
}
