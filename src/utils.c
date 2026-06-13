#include "../include/kverify.h"

const char *scenario_names[SCENARIO_COUNT] = {
    "RWX_ALLOC",
    "RWX_EXEC",
    "HIDE_PROC",
    "HIDE_COMM",
    "BYPASS_WX",
    "BYPASS_ASLR",
    "BPF_VALIDATE",
    "YARA_SCAN"
};

const char *mitre_ids[SCENARIO_COUNT] = {
    "T1055.001",
    "T1055",
    "T1564",
    "T1564",
    "T1562.001",
    "T1562.001",
    "T1059",
    "T1560"
};

void trim_newline(char *s)
{
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'))
        s[--len] = '\0';
}

int read_proc_line(const char *path, char *buf, size_t size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, size - 1);
    int close_ret = close(fd);
    (void)close_ret;

    if (n <= 0) return -1;

    buf[n] = '\0';
    trim_newline(buf);
    return 0;
}

int path_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

int run_command(char *const argv[], char *output, size_t out_size)
{
    int pipefd[2];
    if (pipe(pipefd) == -1) return -1;

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) _exit(1);
        if (dup2(pipefd[1], STDERR_FILENO) == -1) _exit(1);
        close(pipefd[1]);
        if (argv[0] == NULL) _exit(1);
        execvp(argv[0], argv);
        _exit(1);
    }

    close(pipefd[1]);
    size_t total = 0;
    while (total < out_size - 1) {
        ssize_t n = read(pipefd[0], output + total, out_size - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    output[total] = '\0';
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static const char *result_label(TestResult r)
{
    switch (r) {
        case RESULT_PASS:  return "PASS";
        case RESULT_FAIL:  return "FAIL";
        case RESULT_WARN:  return "WARN";
        case RESULT_SKIP:  return "SKIP";
        default:           return "ERROR";
    }
}

static const char *result_color(TestResult r)
{
    switch (r) {
        case RESULT_PASS:  return CLR_GREEN;
        case RESULT_FAIL:  return CLR_RED;
        case RESULT_WARN:  return CLR_YELLOW;
        case RESULT_SKIP:  return CLR_CYAN;
        default:           return CLR_MAGENTA;
    }
}

static void print_progress_bar(int value, int max, int width)
{
    int filled = (max > 0) ? (value * width / max) : 0;
    if (filled > width) filled = width;
    for (int i = 0; i < width; i++) {
        if (i < filled)
            printf(CLR_BOLD_GREEN "\xe2\x96\x88" CLR_RESET);
        else
            printf("\xe2\x96\x91");
    }
}

void export_results_terminal(ScenarioResult *results, int count)
{
    printf("\n");
    printf("  " CLR_BOLD_MAGENTA "-- Detection Matrix" CLR_RESET "\n");
    printf("  %-14s %-8s %-12s %s\n", "", "RESULT", "K-SCANNER", "LINSPEC");

    int total_exec_pass = 0, total_exec_fail = 0, total_exec_skip = 0;
    int total_detect_kscanner = 0, total_detect_linspec = 0;

    for (int i = 0; i < count; i++) {
        ScenarioResult *r = &results[i];

        switch (r->execution_result) {
            case RESULT_PASS: total_exec_pass++; break;
            case RESULT_FAIL: total_exec_fail++; break;
            case RESULT_SKIP: total_exec_skip++; break;
            default: break;
        }
        if (r->detection.kscanner_detected) total_detect_kscanner++;
        if (r->detection.linspec_detected)  total_detect_linspec++;

        int e_idx = (r->type >= 0 && r->type < SCENARIO_COUNT) ? r->type : 0;
        printf("  %-14s ", scenario_names[e_idx]);
        printf("%s%-8s" CLR_RESET " ",
               result_color(r->execution_result), result_label(r->execution_result));
        printf("%s%-12s" CLR_RESET,
               r->detection.kscanner_detected ? CLR_RED : CLR_GREEN,
               r->detection.kscanner_detected ? "\xe2\x97\x8f detect" : "\xe2\x97\x8b miss");
        printf(" %s%s" CLR_RESET,
               r->detection.linspec_detected ? CLR_RED : CLR_GREEN,
               r->detection.linspec_detected ? "\xe2\x97\x8f detect" : "\xe2\x97\x8b miss");
        printf("\n");
    }

    printf("\n");
    printf("  " CLR_BOLD_MAGENTA "-- Coverage" CLR_RESET "\n");
    printf("  K-Scanner  ");
    print_progress_bar(total_detect_kscanner, count, 12);
    printf("  %d/%d  (%d%%)\n", total_detect_kscanner, count,
           count > 0 ? (total_detect_kscanner * 100 / count) : 0);
    printf("  LinSpec    ");
    print_progress_bar(total_detect_linspec, count, 12);
    printf("  %d/%d  (%d%%)\n", total_detect_linspec, count,
           count > 0 ? (total_detect_linspec * 100 / count) : 0);

    printf("\n");
    printf("  " CLR_BOLD_MAGENTA "-- Summary" CLR_RESET "\n");
    printf("  %d total  ", count);
    for (int i = 0; i < count; i++) {
        switch (results[i].execution_result) {
            case RESULT_PASS:  printf(CLR_GREEN "\xe2\x97\x8f" CLR_RESET); break;
            case RESULT_FAIL:  printf(CLR_RED "\xe2\x97\x8b" CLR_RESET); break;
            case RESULT_WARN:  printf(CLR_YELLOW "\xe2\x97\x90" CLR_RESET); break;
            case RESULT_SKIP:  printf(CLR_CYAN "\xe2\x97\x8b" CLR_RESET); break;
            default:           printf("?"); break;
        }
    }
    printf("  " CLR_GREEN "%d pass" CLR_RESET "  ", total_exec_pass);
    printf(CLR_RED "%d fail" CLR_RESET "  ", total_exec_fail);
    printf(CLR_CYAN "%d skip" CLR_RESET "\n", total_exec_skip);

    printf("\n");
    printf("  " CLR_GREEN "\xe2\x97\x8f" CLR_RESET " Validation complete.\n");
}

void export_results_compact(ScenarioResult *results, int count,
                            const char notes[][MAX_PATH_LEN])
{
    (void)notes;

    int total_pass = 0;
    int total_detect_kscanner = 0, total_detect_linspec = 0;

    printf("\n");
    printf("  " CLR_BOLD_YELLOW "\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90" CLR_RESET "\n");
    printf("   " CLR_BOLD_YELLOW " RUN SEQUENCE INITIATED" CLR_RESET "\n");
    printf("  " CLR_BOLD_YELLOW "\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90" CLR_RESET "\n");
    printf("\n");

    for (int i = 0; i < count; i++) {
        ScenarioResult *r = &results[i];
        int idx = (r->type >= 0 && r->type < SCENARIO_COUNT) ? r->type : 0;

        if (r->execution_result == RESULT_PASS) {
            total_pass++;
        }
        if (r->detection.kscanner_detected) total_detect_kscanner++;
        if (r->detection.linspec_detected)  total_detect_linspec++;

        const char *label;
        switch (r->execution_result) {
            case RESULT_PASS: label = "PASS"; break;
            case RESULT_FAIL: label = "FAIL"; break;
            case RESULT_WARN: label = "WARN"; break;
            case RESULT_SKIP: label = "SKIP"; break;
            default:          label = "ERR";  break;
        }

        const char *ks_check = r->detection.kscanner_detected
                               ? "\xe2\x9c\x94" : "\xe2\x9c\x98";
        const char *ls_check = r->detection.linspec_detected
                               ? "\xe2\x9c\x94" : "\xe2\x9c\x98";

        printf("  " CLR_YELLOW " [%02d/%02d] %s " CLR_RESET,
               i + 1, count, scenario_names[idx]);

        int name_len = (int)strlen(scenario_names[idx]);
        int dot_count = 16 - name_len;
        if (dot_count < 1) dot_count = 1;
        for (int d = 0; d < dot_count; d++) putchar('.');

        printf("  " CLR_BOLD_YELLOW "%-4s" CLR_RESET
               "  [" CLR_YELLOW "KS:%s" CLR_RESET
               "  " CLR_YELLOW "LS:%s" CLR_RESET
               "]  " CLR_CYAN "%s" CLR_RESET "\n",
               label, ks_check, ls_check, mitre_ids[idx]);
    }

    printf("\n");
    printf("  " CLR_BOLD_YELLOW "\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90" CLR_RESET "\n");
    printf("   " CLR_BOLD_YELLOW " FINAL ASSESSMENT" CLR_RESET "\n");
    printf("  " CLR_BOLD_YELLOW "\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90" CLR_RESET "\n");
    printf("\n");

    int total_gaps = 0;
    for (int i = 0; i < count; i++) {
        if (!results[i].detection.kscanner_detected && !results[i].detection.linspec_detected)
            total_gaps++;
    }

    int bar_values[4] = { total_pass, total_detect_kscanner, total_detect_linspec, total_gaps };
    const char *bar_labels[4] = {
        "adversarial actions succeeded",
        "detected by K-Scanner",
        "detected by LinSpec",
        "unmonitored gaps (no KS or LS coverage)"
    };

    for (int b = 0; b < 4; b++) {
        int value = bar_values[b];
        int max   = count;
        int width = 10;
        int filled = (max > 0) ? (value * width / max) : 0;
        if (filled > width) filled = width;

        printf("  " CLR_YELLOW " [");
        for (int p = 0; p < width; p++) {
            if (p < filled)
                printf(CLR_BOLD_YELLOW "\xe2\x96\x88" CLR_RESET);
            else
                printf(CLR_YELLOW "\xe2\x96\x91" CLR_RESET);
        }
        printf(CLR_YELLOW "]  %d/%d  (%d%%)" CLR_RESET "  %s\n",
               value, max, max > 0 ? (value * 100 / max) : 0,
               bar_labels[b]);
    }

    printf("\n");
    printf("   STATUS:  " CLR_MAGENTA "Purple Team Validation Complete" CLR_RESET "\n");
    printf("  " CLR_BOLD_YELLOW "\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90" CLR_RESET "\n");
    printf("\n");
}

static void write_json_escaped(FILE *f, const char *s)
{
    putc('"', f);
    while (*s) {
        switch (*s) {
            case '"':  fprintf(f, "\\\""); break;
            case '\\': fprintf(f, "\\\\"); break;
            case '\n': fprintf(f, "\\n");  break;
            case '\r': fprintf(f, "\\r");  break;
            case '\t': fprintf(f, "\\t");  break;
            default:   putc(*s, f);        break;
        }
        s++;
    }
    putc('"', f);
}

static void write_csv_field(FILE *f, const char *s)
{
    int needs_quote = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            needs_quote = 1;
            break;
        }
    }
    if (needs_quote) {
        putc('"', f);
        while (*s) {
            if (*s == '"') fprintf(f, "\"\"");
            else putc(*s, f);
            s++;
        }
        putc('"', f);
    } else {
        fprintf(f, "%s", s);
    }
}

void export_results_json(ScenarioResult *results, int count, const char *filename)
{
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "  Error: could not write %s\n", filename);
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"K-Verify\",\n");
    fprintf(f, "  \"version\": \"2.0.0\",\n");
    fprintf(f, "  \"scenarios\": [\n");

    for (int i = 0; i < count; i++) {
        ScenarioResult *r = &results[i];
        int j_idx = (r->type >= 0 && r->type < SCENARIO_COUNT) ? r->type : 0;
        fprintf(f, "    {\n");
        fprintf(f, "      \"scenario\": \"%s\",\n", scenario_names[j_idx]);
        fprintf(f, "      \"mitre_id\": \"%s\",\n", mitre_ids[j_idx]);
        fprintf(f, "      \"execution_result\": \"%s\",\n", result_label(r->execution_result));
        fprintf(f, "      \"detection\": {\n");
        fprintf(f, "        \"kscanner\": %s,\n",
                r->detection.kscanner_detected ? "true" : "false");
        fprintf(f, "        \"linspec\": %s\n",
                r->detection.linspec_detected ? "true" : "false");
        fprintf(f, "      },\n");
        fprintf(f, "      \"notes\": ");
        write_json_escaped(f, r->detection.notes);
        fprintf(f, "\n");
        fprintf(f, "    }%s\n", (i + 1 < count) ? "," : "");
    }

    fprintf(f, "   ]\n");
    fprintf(f, "}\n");
    if (fclose(f) != 0) {
        fprintf(stderr, "  Error: failed to write %s (disk full?)\n", filename);
    }
    printf("  JSON: %s\n", filename);
}

void export_results_csv(ScenarioResult *results, int count, const char *filename)
{
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "  Error: could not write %s\n", filename);
        return;
    }

    fprintf(f, "scenario,mitre_id,execution_result,kscanner_detected,linspec_detected,notes\n");
    for (int i = 0; i < count; i++) {
        ScenarioResult *r = &results[i];
        int c_idx = (r->type >= 0 && r->type < SCENARIO_COUNT) ? r->type : 0;
        fprintf(f, "%s,%s,%s,%d,%d,",
                scenario_names[c_idx],
                mitre_ids[c_idx],
                result_label(r->execution_result),
                r->detection.kscanner_detected,
                r->detection.linspec_detected);
        write_csv_field(f, r->detection.notes);
        fprintf(f, "\n");
    }

    if (fclose(f) != 0) {
        fprintf(stderr, "  Error: failed to write %s (disk full?)\n", filename);
    }
    printf("  CSV:  %s\n", filename);
}

void print_banner(void)
{
    printf("\n");
    printf("        " CLR_YELLOW "\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x97" CLR_RESET "\n");
    printf("        " CLR_YELLOW "\xe2\x95\x91            K-Verify               \xe2\x95\x91" CLR_RESET "\n");
    printf("        " CLR_YELLOW "\xe2\x95\x91     Purple Team \xe2\x80\x94 Adversarial     \xe2\x95\x91" CLR_RESET "\n");
    printf("        " CLR_YELLOW "\xe2\x95\x91          Validation               \xe2\x95\x91" CLR_RESET "\n");
    printf("        " CLR_YELLOW "\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9d" CLR_RESET "\n");
    printf("\n");
    if (geteuid() != 0) {
        printf("  " CLR_BOLD_YELLOW "\xe2\x9a\xa0" CLR_RESET " " CLR_YELLOW "Not running as root" CLR_RESET " " CLR_YELLOW "\xe2\x80\x94 some tests may fail." CLR_RESET "\n\n");
    }
}

void cleanup_children(void)
{
    pid_t pgid = getpgid(0);
    if (pgid > 0) {
        kill(-pgid, SIGTERM);
        usleep(100000);
        kill(-pgid, SIGKILL);
    }
    printf("  Children cleaned up.\n");
}

void init_result(ScenarioResult *r, ScenarioType type)
{
    r->type = type;
    r->execution_result = RESULT_SKIP;
    r->detection.kscanner_detected = 0;
    r->detection.linspec_detected = 0;
    r->detection.notes[0] = '\0';
}
