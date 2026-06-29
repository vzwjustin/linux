// SPDX-License-Identifier: LGPL-2.1+

#include <kunit/test.h>
#include <linux/time.h>

int time_test_last_day_of_month_rs(long year, int month);
void time_test_advance_date_rs(long *year, int *month, int *mday, int *yday);

/*
 * Checks every day in a 160000 years interval centered at 1970-01-01
 * against the expected result.
 */
static void time64_to_tm_test_date_range(struct kunit *test)
{
	/*
	 * 80000 years	= (80000 / 400) * 400 years
	 *		= (80000 / 400) * 146097 days
	 *		= (80000 / 400) * 146097 * 86400 seconds
	 */
	time64_t total_secs = ((time64_t) 80000) / 400 * 146097 * 86400;
	long year = 1970 - 80000;
	int month = 1;
	int mdday = 1;
	int yday = 0;

	struct tm result;
	time64_t secs;
	s64 days;

	for (secs = -total_secs; secs <= total_secs; secs += 86400) {

		time64_to_tm(secs, 0, &result);

		days = div_s64(secs, 86400);

		#define FAIL_MSG "%05ld/%02d/%02d (%2d) : %lld", \
			year, month, mdday, yday, days

		KUNIT_ASSERT_EQ_MSG(test, year - 1900, result.tm_year, FAIL_MSG);
		KUNIT_ASSERT_EQ_MSG(test, month - 1, result.tm_mon, FAIL_MSG);
		KUNIT_ASSERT_EQ_MSG(test, mdday, result.tm_mday, FAIL_MSG);
		KUNIT_ASSERT_EQ_MSG(test, yday, result.tm_yday, FAIL_MSG);

		time_test_advance_date_rs(&year, &month, &mdday, &yday);
	}
}

static struct kunit_case time_test_cases[] = {
	KUNIT_CASE_SLOW(time64_to_tm_test_date_range),
	{}
};

static struct kunit_suite time_test_suite = {
	.name = "time_test_cases",
	.test_cases = time_test_cases,
};

kunit_test_suite(time_test_suite);
MODULE_DESCRIPTION("time unit test suite");
MODULE_LICENSE("GPL");
