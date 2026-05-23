#include "../include/kverify.h"
#include "../include/modules.h"

int verify_kscanner_rwx(ScenarioResult *result)
{
    char maps_path[MAX_PATH_LEN];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", getpid());

    FILE *f = fopen(maps_path, "r");
    if (!f) {
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not open maps");
        return 0;
    }

    char line[MAX_LINE_LEN];
    int rwx_count = 0;

    while (fgets(line, sizeof(line), f)) {
        char perms[8] = {0};
        char path_buf[MAX_PATH_LEN] = {0};

        unsigned long start, end;
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3)
            continue;

        if (strncmp(perms, "rwx", 3) == 0) {
            rwx_count++;

            char *path_part = strchr(line, '/');
            if (path_part) {
                trim_newline(path_part);
                snprintf(path_buf, sizeof(path_buf), "%s", path_part);
            } else {
                snprintf(path_buf, sizeof(path_buf), "[anonymous]");
            }

            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "RWX region: [%lx-%lx] %s", start, end, path_buf);
        }
    }
    fclose(f);

    if (rwx_count == 0) {
        result->detection.kscanner_detected = 0;
        return 0;
    }

    result->detection.kscanner_detected = 1;
    return rwx_count;
}

int verify_linspec_hardening(ScenarioResult *result)
{
    char buf[MAX_LINE_LEN];
    int vulnerabilities = 0;

    struct {
        const char *path;
        const char *desc;
        int *detected;
    } checks[] = {
        {"/proc/sys/kernel/kptr_restrict",     "kptr_restrict",       NULL},
        {"/proc/sys/kernel/dmesg_restrict",    "dmesg_restrict",      NULL},
        {"/proc/sys/kernel/kexec_load_disabled", "kexec_disabled",    NULL},
        {"/proc/sys/kernel/randomize_va_space", "ASLR",               NULL},
    };

    for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        if (read_proc_line(checks[i].path, buf, sizeof(buf)) == 0) {
            int val = atoi(buf);
            if (val == 0) {
                vulnerabilities++;
            }
        }
    }

    if (vulnerabilities > 0) {
        result->detection.linspec_detected = 1;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "%d hardening gaps (LinSpec would flag)",
                 vulnerabilities);
        return vulnerabilities;
    }

    result->detection.linspec_detected = 0;
    snprintf(result->detection.notes, sizeof(result->detection.notes),
             "Kernel appears hardened (no gaps detected)");
    return 0;
}

int verify_full(ScenarioResult *results, int count)
{
    if (!results || count <= 0) return -1;

    for (int i = 0; i < count; i++) {
        ScenarioResult *r = &results[i];

        switch (r->type) {
            case SCENARIO_RWX_ALLOC:
            case SCENARIO_RWX_EXEC:
                verify_kscanner_rwx(r);

                if (r->detection.kscanner_detected)
                    r->detection.linspec_detected = 0;
                break;

            case SCENARIO_HIDE_PROC:
            case SCENARIO_HIDE_COMM:
                r->detection.linspec_detected = 0;
                break;

            case SCENARIO_BYPASS_WX:
                r->detection.kscanner_detected = 0;
                verify_linspec_hardening(r);
                break;

            case SCENARIO_BYPASS_ASLR:
                r->detection.kscanner_detected = 0;
                verify_linspec_hardening(r);
                break;

            default:
                break;
        }
    }

    return 0;
}
