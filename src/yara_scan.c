#include "../include/kverify.h"
#include "../include/modules.h"

TestResult yara_scan(ScenarioResult *result)
{
    char output[4096];

    int ret = run_command((char *[]){"which", "yara", NULL}, output, sizeof(output));
    if (ret != 0) {
        result->execution_result = RESULT_SKIP;
        result->detection.kscanner_detected = 0;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "yara not installed, skipping YARA scan");
        return RESULT_SKIP;
    }

    ret = run_command((char *[]){"which", "yarac", NULL}, output, sizeof(output));
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

    char rule_path[] = "/tmp/kv_yara_rule_XXXXXX";
    char data_path[] = "/tmp/kv_yara_data_XXXXXX";
    int rule_fd = mkstemp(rule_path);
    int data_fd = mkstemp(data_path);

    if (rule_fd < 0 || data_fd < 0) {
        if (rule_fd >= 0) close(rule_fd);
        if (data_fd >= 0) close(data_fd);
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not create temp files");
        return RESULT_ERROR;
    }

    FILE *f = fdopen(rule_fd, "w");
    if (!f) {
        close(rule_fd);
        unlink(rule_path);
        close(data_fd);
        unlink(data_path);
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not open rule temp file");
        return RESULT_ERROR;
    }
    fprintf(f, "%s", test_rule);
    fclose(f);

    FILE *df = fdopen(data_fd, "wb");
    if (!df) {
        close(data_fd);
        unlink(data_path);
        unlink(rule_path);
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not open data temp file");
        return RESULT_ERROR;
    }
    fwrite(test_data, 1, 13, df);
    fclose(df);

    ret = run_command((char *[]){"yara", rule_path, data_path, NULL}, output, sizeof(output));

    unlink(rule_path);
    unlink(data_path);

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
