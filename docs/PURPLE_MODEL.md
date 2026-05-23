# Purple Team Model

## Definition

K-Verify operates under a **Purple Team** framework, which integrates adversarial simulation (Red) with defensive detection validation (Blue) within a single tool.

The core principle: **every attack tests a specific defense**, and every result produces a **detection gap analysis**.

## Methodology

### Three-Phase Execution

1. **Adversarial Phase:** Execute a controlled attack technique (RWX allocation, process masquerading, mitigation bypass)
2. **Detection Phase:** Query the same kernel interfaces that K-Scanner and LinSpec use
3. **Validation Phase:** Compare adversarial success against detection coverage

### Attack-Defense Mapping

| Adversarial Action | Blue Tool | Detection Mechanism |
|---|---|---|
| RWX mmap | K-Scanner | /proc/[PID]/maps permission parsing |
| Shellcode execution | K-Scanner | RWX + writable + executable region detection |
| Process masquerading | K-Scanner | /proc/[PID]/comm and cmdline validation |
| W^X bypass attempt | LinSpec | kernel.exec-shield, mmap_min_addr |
| ASLR state change | LinSpec | randomize_va_space audit |

## Classification

Results are classified across two axes:

- **Execution Result:** Did the adversarial action succeed? (PASS / FAIL / WARN / SKIP / ERROR)
- **Detection Result:** Did the defensive tool detect it? (DETECT / MISS)

The combination produces four Purple Team outcomes:

| Execution | Detection | Interpretation |
|---|---|---|
| PASS | MISS | **Gap:** Attack works and is invisible to defense |
| PASS | DETECT | **Validated:** Attack works but defense catches it |
| FAIL | MISS | **Mitigated:** Defense blocks the attack (expected) |
| FAIL | DETECT | **False Positive?:** Attack failed but defense still flagged |

## Operational Integrity

- All adversarial actions are **contained** to the local process or immediate children
- No persistent system modifications
- No network exfiltration or lateral movement
- Shellcode is limited to exit(0) — benign, verifiable, and trivially inspected
- Child processes are tracked and can be reaped via `--cleanup`
