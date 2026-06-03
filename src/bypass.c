#include "../include/kverify.h"
#include "../include/modules.h"

TestResult bypass_wx_check(ScenarioResult *result)
{
    char buf[MAX_LINE_LEN];
    int wx_enforced = 0;

    if (read_proc_line(PROC_EXEC_SHIELD, buf, sizeof(buf)) == 0) {
        if (atoi(buf) > 0) wx_enforced = 1;
    }

    if (read_proc_line(PROC_MMAP_MIN_ADDR, buf, sizeof(buf)) == 0) {
        unsigned long min_addr = strtoul(buf, NULL, 10);
        if (min_addr > 0) wx_enforced++;
    }

    void *test = mmap(NULL, 4096,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (test == MAP_FAILED) {
        if (errno == EPERM || errno == EACCES) {
            result->execution_result = RESULT_FAIL;
            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "W^X enforced: mmap RWX blocked (%s)", strerror(errno));
            result->detection.linspec_detected = 1;
            return RESULT_FAIL;
        }
        result->execution_result = RESULT_WARN;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "mmap RWX failed: %s", strerror(errno));
        return RESULT_WARN;
    }

    munmap(test, 4096);

    result->execution_result = RESULT_PASS;
    result->detection.linspec_detected = 0;
    snprintf(result->detection.notes, sizeof(result->detection.notes),
             "W^X bypass: RWX ok (exec-shield=%d, mmap_min=%.100s)",
             wx_enforced, buf);
    return RESULT_PASS;
}

TestResult bypass_aslr_assess(ScenarioResult *result)
{
    char buf[MAX_LINE_LEN];

    if (read_proc_line(PROC_ASLR, buf, sizeof(buf)) == 0) {
        int val = atoi(buf);
        switch (val) {
            case 0:
                result->execution_result = RESULT_PASS;
                snprintf(result->detection.notes, sizeof(result->detection.notes),
                         "ASLR disabled (randomize_va_space=0)");
                result->detection.linspec_detected = 1;
                return RESULT_PASS;
            case 1:
                result->execution_result = RESULT_WARN;
                snprintf(result->detection.notes, sizeof(result->detection.notes),
                         "ASLR partial (randomize_va_space=1)");
                result->detection.linspec_detected = 0;
                return RESULT_WARN;
            case 2:
                result->execution_result = RESULT_FAIL;
                snprintf(result->detection.notes, sizeof(result->detection.notes),
                         "ASLR full (randomize_va_space=2)");
                result->detection.linspec_detected = 0;
                return RESULT_FAIL;
            default:
                result->execution_result = RESULT_WARN;
                snprintf(result->detection.notes, sizeof(result->detection.notes),
                         "ASLR unknown state (randomize_va_space=%d)", val);
                return RESULT_WARN;
        }
    }

    result->execution_result = RESULT_SKIP;
    snprintf(result->detection.notes, sizeof(result->detection.notes),
             "Could not read ASLR state");
    return RESULT_SKIP;
}
