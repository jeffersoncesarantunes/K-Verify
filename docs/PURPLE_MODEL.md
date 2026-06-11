# Purple Team Model

## Definition

K-Verify works within a **Purple Team** framework, which means it blends adversarial simulation (Red) with defensive detection validation (Blue) into a single tool. The core idea is simple: every attack tests a specific defense, and every result feeds into a detection gap analysis.

## Methodology

### Three-Phase Execution

The tool runs through three phases. First is the **Adversarial Phase**, where it executes a controlled attack technique -- something like an RWX allocation, process masquerading, or mitigation bypass. Next is the **Detection Phase**, where it queries the same kernel interfaces K-Scanner and LinSpec would read. Finally, the **Validation Phase** compares whether the adversarial action succeeded against whether the defense caught it.

### Attack-Defense Mapping

| Adversarial Action | Blue Tool | Detection Mechanism |
|---|---|---|
| RWX mmap | K-Scanner | /proc/[PID]/maps permission parsing |
| Shellcode execution | K-Scanner | RWX + writable + executable region detection |
| Process masquerading | K-Scanner | /proc/[PID]/comm and cmdline validation |
| W^X bypass attempt | LinSpec | kernel.exec-shield, mmap_min_addr |
| ASLR state change | LinSpec | randomize_va_space audit |
| eBPF readiness | K-Scanner | BTF availability + BPF JIT hardening |
| YARA signature match | K-Scanner | YARA rule engine against memory dumps |

## Classification

Results get classified across two axes. The **Execution Result** tells you whether the adversarial action succeeded -- PASS, FAIL, WARN, SKIP, or ERROR. The **Detection Result** tells you whether the defensive tool caught it -- DETECT or MISS. Combining them gives four Purple Team outcomes:

| Execution | Detection | Interpretation |
|---|---|---|
| PASS | MISS | **Gap:** Attack works and is invisible to defense |
| PASS | DETECT | **Validated:** Attack works but defense catches it |
| FAIL | MISS | **Mitigated:** Defense blocks the attack (expected) |
| FAIL | DETECT | **False Positive?:** Attack failed but defense still flagged |

## Operational Integrity

Every adversarial action is contained to the local process or its immediate children. There are no persistent system modifications, no network exfiltration, no lateral movement. Shellcode is limited to exit(0) -- it's benign, verifiable, and trivially inspectable. Child processes are tracked and can be cleaned up via `--cleanup`.
