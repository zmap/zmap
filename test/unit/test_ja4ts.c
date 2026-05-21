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

/* JA4T tests: verify compute_ja4ts against the exact byte sequences that
 * set_tcp_options() emits for each OS profile (window is always 65535). */

static void test_ja4t_smallest_probes(void)
{
	/* set_mss_option only: kind=2, len=4, MSS=1460 */
	uint8_t opts[] = {0x02, 0x04, 0x05, 0xb4};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 65535, out, sizeof(out));
	expect_eq_str("65535_2_1460_00", out, "ja4t_smallest_probes");
}

static void test_ja4t_windows(void)
{
	/* set_mss_option + set_nop_plus_windows_scale(WINDOWS) + set_nop_plus_sack_permitted */
	uint8_t opts[] = {
		0x02, 0x04, 0x05, 0xb4,  /* MSS 1460 */
		0x01,                    /* NOP */
		0x03, 0x03, 0x08,        /* WScale 8 */
		0x01,                    /* NOP */
		0x01,                    /* NOP */
		0x04, 0x02,              /* SACK-perm */
	};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 65535, out, sizeof(out));
	expect_eq_str("65535_2-1-3-1-1-4_1460_8", out, "ja4t_windows");
}

static void test_ja4t_linux(void)
{
	/* set_mss_option + set_sack_permitted_with_timestamp + set_nop_plus_windows_scale(LINUX) */
	uint8_t opts[] = {
		0x02, 0x04, 0x05, 0xb4,           /* MSS 1460 */
		0x04, 0x02,                       /* SACK-perm */
		0x08, 0x0a, 0,0,0,0, 0,0,0,0,     /* Timestamps (value irrelevant to fingerprint) */
		0x01,                             /* NOP */
		0x03, 0x03, 0x07,                 /* WScale 7 */
	};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 65535, out, sizeof(out));
	expect_eq_str("65535_2-4-8-1-3_1460_7", out, "ja4t_linux");
}

static void test_ja4t_bsd(void)
{
	/* set_mss_option + set_nop_plus_windows_scale(BSD) + set_timestamp_option_with_nops
	 * + set_sack_permitted_plus_eol */
	uint8_t opts[] = {
		0x02, 0x04, 0x05, 0xb4,           /* MSS 1460 */
		0x01,                             /* NOP */
		0x03, 0x03, 0x06,                 /* WScale 6 */
		0x01,                             /* NOP */
		0x01,                             /* NOP */
		0x08, 0x0a, 0,0,0,0, 0,0,0,0,     /* Timestamps */
		0x04, 0x02,                       /* SACK-perm */
		0x00,                             /* EOL */
	};
	char out[256];
	compute_ja4ts(opts, sizeof(opts), 65535, out, sizeof(out));
	/* EOL (kind 0) is recorded before the break, so it appears in the kinds list */
	expect_eq_str("65535_2-1-3-1-1-8-4-0_1460_6", out, "ja4t_bsd");
}

int main(void)
{
	test_no_options();
	test_mss_only();
	test_linux_like();
	test_wscale_zero();
	test_malformed_length();
	test_eol_stops();

	test_ja4t_smallest_probes();
	test_ja4t_windows();
	test_ja4t_linux();
	test_ja4t_bsd();

	return failures == 0 ? 0 : 1;
}
