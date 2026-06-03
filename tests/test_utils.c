#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/kverify.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static void test_assert(const char *name, int condition)
{
    tests_run++;
    if (condition) {
        tests_passed++;
        printf("  " CLR_GREEN "\xe2\x9c\x93" CLR_RESET " %s\n", name);
    } else {
        tests_failed++;
        printf("  " CLR_RED "\xe2\x9c\x98" CLR_RESET " %s\n", name);
    }
}

static void test_trim_newline(void)
{
    char s1[] = "hello\n";
    trim_newline(s1);
    test_assert("trim_newline removes trailing newline", strcmp(s1, "hello") == 0);

    char s2[] = "hello\r\n";
    trim_newline(s2);
    test_assert("trim_newline removes CRLF", strcmp(s2, "hello") == 0);

    char s3[] = "hello";
    trim_newline(s3);
    test_assert("trim_newline noop on clean string", strcmp(s3, "hello") == 0);

    trim_newline(NULL);
    test_assert("trim_newline handles NULL", 1);
}

static void test_scenario_names(void)
{
    test_assert("scenario_names[0] is RWX_ALLOC",
                strcmp(scenario_names[0], "RWX_ALLOC") == 0);
    test_assert("scenario_names[SCENARIO_COUNT-1] exists",
                scenario_names[SCENARIO_COUNT - 1] != NULL);
    test_assert("SCENARIO_COUNT matches array size",
                SCENARIO_COUNT == 8);
}

static void test_mitre_ids(void)
{
    test_assert("mitre_ids[0] is T1055.001",
                strcmp(mitre_ids[0], "T1055.001") == 0);
    test_assert("mitre_ids[4] is T1562.001",
                strcmp(mitre_ids[4], "T1562.001") == 0);
    test_assert("mitre_ids[6] is T1059 (BPF)",
                strcmp(mitre_ids[6], "T1059") == 0);
    test_assert("mitre_ids[7] is T1560 (YARA)",
                strcmp(mitre_ids[7], "T1560") == 0);
}

static void test_init_result(void)
{
    ScenarioResult r;
    init_result(&r, SCENARIO_RWX_ALLOC);
    test_assert("init_result sets type correctly", r.type == SCENARIO_RWX_ALLOC);
    test_assert("init_result sets result to SKIP", r.execution_result == RESULT_SKIP);
    test_assert("init_result clears kscanner_detected", r.detection.kscanner_detected == 0);
    test_assert("init_result clears linspec_detected", r.detection.linspec_detected == 0);
    test_assert("init_result clears notes", strlen(r.detection.notes) == 0);
}

static void test_path_exists(void)
{
    test_assert("path_exists on /tmp returns 1", path_exists("/tmp") == 1);
    test_assert("path_exists on nonexistent returns 0",
                path_exists("/tmp/kv_nonexistent_xxxx") == 0);
}

static void test_read_proc_line(void)
{
    char buf[MAX_LINE_LEN];
    int ret = read_proc_line("/proc/self/comm", buf, sizeof(buf));
    test_assert("read_proc_line on /proc/self/comm succeeds", ret == 0);
    test_assert("read_proc_line result is non-empty", strlen(buf) > 0);
}

int main(void)
{
    printf("\n  " CLR_BOLD_CYAN "K-Verify Test Suite" CLR_RESET "\n");
    printf("  " CLR_CYAN "%s" CLR_RESET "\n\n", "==============================");

    test_trim_newline();
    test_scenario_names();
    test_mitre_ids();
    test_init_result();
    test_path_exists();
    test_read_proc_line();

    printf("\n");
    printf("  " CLR_BOLD_CYAN "Results:" CLR_RESET "\n");
    printf("  Total: %d  ", tests_run);
    printf(CLR_GREEN "Passed: %d" CLR_RESET "  ", tests_passed);
    printf(CLR_RED "Failed: %d" CLR_RESET "\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
