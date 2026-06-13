#include "../include/kverify.h"
#include "../include/modules.h"

TestResult bpf_validate(ScenarioResult *result)
{
    int bpf_capable = 0;
    int btf_available = 0;
    int bpf_jit_harden = -1;
    char buf[MAX_LINE_LEN];

    if (path_exists("/sys/kernel/btf/vmlinux")) {
        btf_available = 1;
        bpf_capable++;
    }

    if (read_proc_line(PROC_BPF_JIT_HARDEN, buf, sizeof(buf)) == 0) {
        char *end;
        long val = strtol(buf, &end, 10);
        if (buf[0] != '\0' && (*end == '\n' || *end == '\0')) {
            bpf_jit_harden = (int)val;
            bpf_capable++;
        }
    }

    if (bpf_capable >= 2) {
        result->execution_result = RESULT_PASS;
        result->detection.kscanner_detected = 1;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "eBPF fully available (BTF=yes, bpf_jit_harden=%d)",
                 bpf_jit_harden);
    } else if (bpf_capable == 1) {
        result->execution_result = RESULT_WARN;
        result->detection.kscanner_detected = 0;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "eBPF partially available (BTF=%s, bpf_jit_harden=%d)",
                 btf_available ? "yes" : "no", bpf_jit_harden);
    } else {
        result->execution_result = RESULT_FAIL;
        result->detection.kscanner_detected = 0;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "eBPF not available (no BTF, no BPF JIT sysctl)");
    }

    return result->execution_result;
}
