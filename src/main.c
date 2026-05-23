#include "../include/kverify.h"
#include "../include/modules.h"

static void print_usage(void)
{
    printf("Usage: kverify [OPTIONS]\n");
    printf("Purple Team adversarial validation suite.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --all              Run all adversarial scenarios (default)\n");
    printf("  --rwx              RWX allocation and execution test\n");
    printf("  --hide             Process hiding and masquerade test\n");
    printf("  --bypass           Mitigation bypass assessment\n");
    printf("  --verify-only      Run verification against existing state\n");
    printf("  --json             Export results in JSON format\n");
    printf("  --csv              Export results in CSV format\n");
    printf("  --output <file>    Output file prefix (default: kverify-report)\n");
    printf("  --cleanup          Kill remaining child processes from tests\n");
    printf("  --help             Show this help message\n");
}

static void cleanup_children(void)
{
    pid_t pgid = getpgid(0);
    if (pgid > 0) {
        kill(-pgid, SIGTERM);
        usleep(100000);
        kill(-pgid, SIGKILL);
    }
    printf("  Children cleaned up.\n");
}

static void init_result(ScenarioResult *r, ScenarioType type)
{
    r->type = type;
    r->execution_result = RESULT_SKIP;
    r->detection.kscanner_detected = 0;
    r->detection.linspec_detected = 0;
    r->detection.notes[0] = '\0';
}

static void print_banner(void)
{
    printf("\n");
    printf("        " CLR_YELLOW "╔══════════════════════════════════════════════════════╗" CLR_RESET "\n");
    printf("        " CLR_YELLOW "║                       K-Verify                       ║" CLR_RESET "\n");
    printf("        " CLR_YELLOW "║         Purple Team - Adversarial Validation         ║" CLR_RESET "\n");
    printf("        " CLR_YELLOW "╚══════════════════════════════════════════════════════╝" CLR_RESET "\n");
    printf("\n");
    if (geteuid() != 0) {
        printf("  " CLR_BOLD_YELLOW "\xe2\x9a\xa0" CLR_RESET " " CLR_YELLOW "Not running as root" CLR_RESET " " CLR_YELLOW "— some tests may fail." CLR_RESET "\n\n");
    }
}

int main(int argc, char *argv[])
{
    int run_all = 1;
    int run_rwx = 0;
    int run_hide = 0;
    int run_bypass = 0;
    int run_verify_only = 0;
    ExportFormat format = EXPORT_TERMINAL;
    const char *output_prefix = "kverify-report";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        }
        if (strcmp(argv[i], "--all") == 0) {
            run_all = 1;
            continue;
        }
        if (strcmp(argv[i], "--rwx") == 0) {
            run_rwx = 1; run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "--hide") == 0) {
            run_hide = 1; run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "--bypass") == 0) {
            run_bypass = 1; run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "--verify-only") == 0) {
            run_verify_only = 1; run_all = 0;
            continue;
        }
        if (strcmp(argv[i], "--cleanup") == 0) {
            cleanup_children();
            return 0;
        }
        if (strcmp(argv[i], "--json") == 0) {
            format = EXPORT_JSON;
            continue;
        }
        if (strcmp(argv[i], "--csv") == 0) {
            format = EXPORT_CSV;
            continue;
        }
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_prefix = argv[++i];
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        fprintf(stderr, "Try --help for usage.\n");
        return 1;
    }

    ScenarioResult results[MAX_SCENARIOS];
    char action_notes[MAX_SCENARIOS][MAX_PATH_LEN];
    int count = 0;

    if (run_all || run_verify_only) {
        run_rwx = run_hide = run_bypass = 1;
    }

    if (format != EXPORT_JSON) {
        print_banner();
    }

    if (run_rwx && !run_verify_only) {
        init_result(&results[count], SCENARIO_RWX_ALLOC);
        void *rwx_addr = rwx_allocate(4096, &results[count]);
        snprintf(action_notes[count], MAX_PATH_LEN, "%s",
                 results[count].detection.notes);
        count++;

        if (rwx_addr) {
            init_result(&results[count], SCENARIO_RWX_EXEC);

            unsigned char shellcode[SHELLCODE_SIZE];
            memset(shellcode, 0, sizeof(shellcode));
#if defined(__x86_64__) || defined(__amd64__)
            shellcode[0] = 0x90;
            shellcode[1] = 0x90;
            shellcode[2] = 0x90;
            shellcode[3] = 0xb8;
            shellcode[4] = 0x3c;
            shellcode[5] = 0x00;
            shellcode[6] = 0x00;
            shellcode[7] = 0x00;
            shellcode[8] = 0x48;
            shellcode[9] = 0x31;
            shellcode[10] = 0xff;
            shellcode[11] = 0x0f;
            shellcode[12] = 0x05;
#elif defined(__i386__)
            shellcode[0] = 0x90;
            shellcode[1] = 0x90;
            shellcode[2] = 0x31;
            shellcode[3] = 0xdb;
            shellcode[4] = 0xb0;
            shellcode[5] = 0x01;
            shellcode[6] = 0xcd;
            shellcode[7] = 0x80;
#else
            shellcode[0] = 0x90;
            shellcode[1] = 0x90;
            shellcode[2] = 0x90;
#endif

            size_t sc_len = 16;
            rwx_execute(rwx_addr, 4096, shellcode, sc_len, &results[count]);
            snprintf(action_notes[count], MAX_PATH_LEN, "%s",
                     results[count].detection.notes);
            count++;

            rwx_release(rwx_addr, 4096);
        }
    }

    if (run_hide && !run_verify_only) {
        init_result(&results[count], SCENARIO_HIDE_PROC);
        pid_t child = hide_fork_masquerade("[kworker/0:0]", &results[count]);
        snprintf(action_notes[count], MAX_PATH_LEN, "%s",
                 results[count].detection.notes);
        count++;

        if (child > 0) {
            int wstatus;
            waitpid(child, &wstatus, WNOHANG);
        }

        init_result(&results[count], SCENARIO_HIDE_COMM);
        hide_argv_masquerade("[kworker/0:1]", &results[count]);
        snprintf(action_notes[count], MAX_PATH_LEN, "%s",
                 results[count].detection.notes);
        count++;
    }

    if (run_bypass && !run_verify_only) {
        init_result(&results[count], SCENARIO_BYPASS_WX);
        bypass_wx_check(&results[count]);
        snprintf(action_notes[count], MAX_PATH_LEN, "%s",
                 results[count].detection.notes);
        count++;

        init_result(&results[count], SCENARIO_BYPASS_ASLR);
        bypass_aslr_assess(&results[count]);
        snprintf(action_notes[count], MAX_PATH_LEN, "%s",
                 results[count].detection.notes);
        count++;
    }

    verify_full(results, count);
    if (run_verify_only) {
        init_result(&results[0], SCENARIO_BYPASS_WX);
        verify_linspec_hardening(&results[0]);
        results[0].execution_result = results[0].detection.linspec_detected
                                      ? RESULT_FAIL : RESULT_PASS;

        init_result(&results[1], SCENARIO_RWX_ALLOC);
        verify_kscanner_rwx(&results[1]);
        results[1].execution_result = results[1].detection.kscanner_detected
                                      ? RESULT_FAIL : RESULT_PASS;

        count = 2;
        memset(action_notes, 0, sizeof(action_notes));
    }

    if (format == EXPORT_TERMINAL) {
        export_results_compact(results, count, action_notes);
    }

    if (format == EXPORT_JSON) {
        char json_path[MAX_PATH_LEN];
        snprintf(json_path, sizeof(json_path), "%s.json", output_prefix);
        export_results_json(results, count, json_path);
    }

    if (format == EXPORT_CSV) {
        char csv_path[MAX_PATH_LEN];
        snprintf(csv_path, sizeof(csv_path), "%s.csv", output_prefix);
        export_results_csv(results, count, csv_path);
    }

    return 0;
}
