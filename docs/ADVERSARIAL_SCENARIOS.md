# Adversarial Scenarios

## Scenario 1: RWX_ALLOC

**Objective:** Allocate anonymous memory with Read-Write-Execute permissions.

**Technique:** `mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`

**MITRE ATT&CK:** [T1055.001](https://attack.mitre.org/techniques/T1055/001/) — Process Injection: Portable Executable Injection

**Red Perspective:** Creates a W^X violation region suitable for shellcode injection.

**Blue Perspective (K-Scanner):** Parses `/proc/[PID]/maps` looking for permission strings containing `rwx`.

**Expected Result:**
- On a system without W^X enforcement: Execution = PASS, K-Scanner = DETECT
- On a system with W^X enforcement (CONFIG_STRICT_MEM_RWX): Execution = FAIL, K-Scanner = MISS

---

## Scenario 2: RWX_EXEC

**Objective:** Write shellcode to an RWX region and execute it via function pointer.

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) — Process Injection

**Technique:**
1. Allocate RWX memory (see Scenario 1)
2. Write NOP + exit(0) shellcode
3. Cast to function pointer and call
4. Child process executes the shellcode

**Shellcode (x86-64):**
```asm
nop
nop
nop
mov eax, 0x3c    ; syscall number for exit
xor edi, edi     ; exit code 0
syscall
```

**Red Perspective:** Demonstrates classic memory corruption payload execution.

**Blue Perspective (K-Scanner):** Same RWX detection as Scenario 1, plus post-execution memory analysis.

---

## Scenario 3: HIDE_PROC

**Objective:** Fork a child and rename it to masquerade as a kernel thread.

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564/) — Hide Artifacts

**Technique:**
1. `fork()` to create a child process
2. `prctl(PR_SET_NAME, "[kworker/0:0]")` to change process name
3. Write to `/proc/[PID]/comm` to persist the name

**Red Perspective:** Masquerades a user process as a kernel thread to evade analyst review.

**Blue Perspective (K-Scanner):** Scans `/proc/[PID]/maps` and `/proc/[PID]/comm`. A process named `[kworker/0:0]` with user-space memory mappings is anomalous.

---

## Scenario 4: HIDE_COMM

**Objective:** Modify `/proc/self/cmdline` to change the visible command line.

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564/) — Hide Artifacts

**Technique:** Open `/proc/self/cmdline` for writing and overwrite with a fake name.

**Red Perspective:** Hides the original command line from `ps`, `top`, and forensic tools.

**Blue Perspective (K-Scanner):** Cross-references `/proc/[PID]/cmdline` with `/proc/[PID]/maps` behavior.

---

## Scenario 5: BYPASS_WX

**Objective:** Test whether W^X enforcement is active on the running kernel.

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Impair Defenses: Disable or Modify Tools

**Technique:** Attempt `mmap` with `PROT_READ|PROT_WRITE|PROT_EXEC`. If it succeeds, W^X is not enforced.

**Red Perspective:** Identifies systems where RWX memory is allowed — prime targets for code injection.

**Blue Perspective (LinSpec):** Audits `/proc/sys/kernel/exec-shield` and `/proc/sys/vm/mmap_min_addr`.

---

## Scenario 6: BYPASS_ASLR

**Objective:** Assess the current ASLR strength.

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Impair Defenses: Disable or Modify Tools

**Technique:** Read `/proc/sys/kernel/randomize_va_space`.

**Red Perspective:** ASLR=0 means no address randomization — exploit development is significantly easier.

**Blue Perspective (LinSpec):** Flags `randomize_va_space=0` as VULN.
