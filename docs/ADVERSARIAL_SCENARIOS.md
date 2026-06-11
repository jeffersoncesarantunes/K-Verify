# Adversarial Scenarios

## Scenario 1: RWX_ALLOC

**Objective:** Allocate anonymous memory with Read-Write-Execute permissions.

**Technique:** `mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`

**MITRE ATT&CK:** [T1055.001](https://attack.mitre.org/techniques/T1055/001/) -- Process Injection: Portable Executable Injection

From the Red side, this creates a W^X violation region that's ready for shellcode injection. From the Blue side, K-Scanner parses `/proc/[PID]/maps` looking for permission strings containing `rwx`.

Expected behavior depends on the kernel. On a system without W^X enforcement, execution passes and K-Scanner detects it. On a system with CONFIG_STRICT_MEM_RWX, execution fails and K-Scanner doesn't see an RWX region to flag.

---

## Scenario 2: RWX_EXEC

**Objective:** Write shellcode to an RWX region and execute it through a function pointer.

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) -- Process Injection

The technique runs in a few steps. Allocate RWX memory (same as Scenario 1), write NOP plus exit(0) shellcode, cast it to a function pointer and call it. A child process handles the actual execution.

**Shellcode (x86-64):**
```asm
nop
nop
nop
mov eax, 0x3c    ; syscall number for exit
xor edi, edi     ; exit code 0
syscall
```

On the Red side, this demonstrates a classic memory corruption payload execution. On the Blue side, K-Scanner uses the same RWX detection as Scenario 1, plus post-execution memory analysis.

---

## Scenario 3: HIDE_PROC

**Objective:** Fork a child process and rename it to look like a kernel thread.

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564/) -- Hide Artifacts

The technique forks a child process, calls `prctl(PR_SET_NAME, "[kworker/0:0]")` to change the process name, and writes to `/proc/[PID]/comm` to persist it. From the Red perspective, this masquerades a user process as a kernel thread to slip past an analyst's review. K-Scanner catches this by scanning `/proc/[PID]/maps` and `/proc/[PID]/comm` -- a process named `[kworker/0:0]` that has user-space memory mappings is anomalous.

---

## Scenario 4: HIDE_COMM

**Objective:** Modify `/proc/self/cmdline` to change the visible command line.

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564/) -- Hide Artifacts

The technique opens `/proc/self/cmdline` for writing and overwrites it with a fake name. From the Red side, this hides the original command line from `ps`, `top`, and forensic tools. K-Scanner cross-references `/proc/[PID]/cmdline` with `/proc/[PID]/maps` behavior to detect the discrepancy.

---

## Scenario 5: BYPASS_WX

**Objective:** Test whether W^X enforcement is active on the running kernel.

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) -- Impair Defenses: Disable or Modify Tools

The technique attempts an `mmap` with `PROT_READ|PROT_WRITE|PROT_EXEC`. If it succeeds, W^X isn't enforced. From the Red side, this identifies systems where RWX memory is allowed -- prime targets for code injection. LinSpec audits `/proc/sys/kernel/exec-shield` and `/proc/sys/vm/mmap_min_addr` to catch it.

---

## Scenario 6: BYPASS_ASLR

**Objective:** Assess the current ASLR strength.

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) -- Impair Defenses: Disable or Modify Tools

The technique reads `/proc/sys/kernel/randomize_va_space`. When ASLR is set to 0, there's no address randomization, which makes exploit development significantly easier. LinSpec flags `randomize_va_space=0` as VULN.

---

## Scenario 7: BPF_VALIDATE

**Objective:** Check whether the kernel supports the eBPF-based detection K-Scanner uses.

**MITRE ATT&CK:** [T1059](https://attack.mitre.org/techniques/T1059/) -- Command and Scripting Interpreter

The technique checks two things: whether `/sys/kernel/btf/vmlinux` exists (BPF Type Format availability) and what `/proc/sys/net/core/bpf_jit_harden` says about JIT hardening state. If eBPF is available, K-Scanner can use real-time kernel telemetry to detect RWX events at the syscall level. K-Scanner's `--bpf` flag uses eBPF `raw_tp/sys_enter` to monitor mmap, mprotect, and shmat in real-time, bypassing /proc parsing limitations entirely.

Expected outcomes: if BTF is available and BPF JIT is active, eBPF telemetry is viable and you get PASS. If BTF is missing or JIT is disabled, it's a WARN with partial support. If neither is available, eBPF telemetry can't function and you get FAIL.

---

## Scenario 8: YARA_SCAN

**Objective:** Test YARA rule detection against known shellcode patterns.

**MITRE ATT&CK:** [T1560](https://attack.mitre.org/techniques/T1560/) -- Archive Collected Data

The technique generates a temporary YARA rule targeting the NOP-plus-exit(0) shellcode pattern, creates a binary file containing the shellcode, runs `yara` against it, then cleans up. YARA lets blue teams define arbitrary binary signatures for memory scanning. K-Scanner's `--yara <rule.yara>` flag applies YARA rules to forensic memory dumps.

Expected outcomes: if yara and yarac are installed, you get PASS when the rule matches or WARN if it doesn't. If YARA isn't installed, the test gets skipped.
