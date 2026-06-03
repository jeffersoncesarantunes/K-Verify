#include "../include/kverify.h"
#include "../include/modules.h"

TestResult yara_scan(ScenarioResult *result)
{
    char output[4096];

    int ret = run_command("which yara 2>/dev/null", output, sizeof(output));
    if (ret != 0) {
        result->execution_result = RESULT_SKIP;
        result->detection.kscanner_detected = 0;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "yara not installed, skipping YARA scan");
        return RESULT_SKIP;
    }

    ret = run_command("which yarac 2>/dev/null", output, sizeof(output));
    if (ret != 0) {
        result->execution_result = RESULT_SKIP;
        result->detection.kscanner_detected = 0;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "yarac not installed, skipping YARA compilation");
        return RESULT_SKIP;
    }

    const char *test_rule =
        "rule test_verify {\n"
        "  meta:\n"
        "    description = \"K-Verify YARA validation rule\"\n"
        "  strings:\n"
        "    $test = { 90 90 90 b8 3c 00 00 00 48 31 ff 0f 05 }\n"
        "  condition:\n"
        "    $test\n"
        "}\n";

    const char *test_data = "\x90\x90\x90\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05";

    FILE *f = fopen("/tmp/kv_yara_rule.yar", "w");
    if (!f) {
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not write test rule");
        return RESULT_ERROR;
    }
    fprintf(f, "%s", test_rule);
    fclose(f);

    f = fopen("/tmp/kv_yara_test.bin", "wb");
    if (!f) {
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not write test data");
        unlink("/tmp/kv_yara_rule.yar");
        return RESULT_ERROR;
    }
    fwrite(test_data, 1, 13, f);
    fclose(f);

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "yara /tmp/kv_yara_rule.yar /tmp/kv_yara_test.bin 2>/dev/null");

    ret = run_command(cmd, output, sizeof(output));

    unlink("/tmp/kv_yara_rule.yar");
    unlink("/tmp/kv_yara_test.bin");

    if (ret == 0 && strlen(output) > 0) {
        result->execution_result = RESULT_PASS;
        result->detection.kscanner_detected = 1;
        char tmp[200];
        snprintf(tmp, sizeof(tmp), "%.190s", output);
        trim_newline(tmp);
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "YARA rule matched: %s", tmp);
    } else {
        result->execution_result = RESULT_WARN;
        result->detection.kscanner_detected = 0;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "YARA scan completed but no match (exit %d)", ret);
    }

    return result->execution_result;
}
