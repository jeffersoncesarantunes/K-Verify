# K-Verify

Purple Team adversarial validation suite for the SYNTROPY forensic ecosystem.


[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-00599C?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-006400?style=flat-square)](#-roadmap)
[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Verify/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/K-Verify/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Verify/codeql.yml?style=flat-square&logo=githubactions&label=CodeQL)](https://github.com/jeffersoncesarantunes/K-Verify/actions/workflows/codeql.yml)
[![Docker](https://img.shields.io/badge/Docker-Multi--stage-2496ED?style=flat-square&logo=docker)](Dockerfile)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Purple%20Team%20%7C%20Adversarial%20Validation-8A2BE2?style=flat-square)](#-overview)
[![YARA](https://img.shields.io/badge/YARA-Rule%20Matching-FF6F00?style=flat-square)](https://virustotal.github.io/yara/)


---

## Etymology & Origin

The name **K-Verify** comes from the Linux **Kernel** — it's the foundational interface that backs every piece of validation logic here. The "K" is a nod to the Kernel, same as **K-Scanner**, its sister project in the SYNTROPY ecosystem. The difference is what each one does. A scanner enumerates state. K-Verify *verifies*: it actively runs adversarial behavior on a live system and checks whether detection mechanisms actually catch it.


---

## Overview

K-Verify is a Purple Team adversarial validation tool built to stress-test the detection layer in the SYNTROPY forensic ecosystem — specifically **K-Scanner** and **LinSpec**.

It runs controlled adversarial actions on a live Linux box, then cross-references each one against the kernel interfaces that those Blue Team tools rely on for detection. Every scenario maps to a **MITRE ATT&CK** technique, and the final report includes a **Detection Gap Analysis** that points out blind spots nobody's covering.

The tool covers a handful of core areas. It allocates writable-plus-executable memory and checks whether K-Scanner picks it up. It forks and renames processes to see how /proc enumeration holds up. It tries W^X and ASLR bypasses and validates LinSpec's auditing. It checks kernel BTF and BPF JIT state for eBPF readiness, and validates YARA pattern matching against shellcode signatures. When live binaries are available, it can actually invoke real K-Scanner and LinSpec instances for true end-to-end testing. Every scenario is tagged with its MITRE ATT&CK technique ID, and the detection gap analysis counts how many scenarios neither tool covers.


---

## Features

K-Verify comes with eight adversarial scenarios, each mapped to a MITRE ATT&CK technique ID. You get eBPF telemetry validation via `--bpf` that checks kernel BTF and BPF JIT readiness, a YARA rule detection test with `--yara` that runs known shellcode patterns through the engine, and live tool integration with `--live` that invokes actual K-Scanner and LinSpec binaries when they're in $PATH. The automated verification cross-references everything against the same kernel interfaces both tools use internally. Output goes to a color-coded Purple Team validation matrix on the terminal, and you can also export structured JSON or CSV for your reporting pipeline. The **Detection Gap Analysis** call out blind spots where no tool provides coverage. **MITRE ATT&CK** IDs show up in terminal output, JSON, and CSV. There's a **Silent JSON mode** (`--json`) that suppresses the banner entirely for CI/CD pipelines. The engine is modular C99 — each scenario lives in its own source file. There's an automated unit test suite via `make test`, a CI/CD pipeline through GitHub Actions, a read-only verification phase that assesses system state without running any attacks, and full child process lifecycle management with a cleanup mode.


---

## MITRE ATT&CK Mapping

Every scenario is mapped to a real MITRE ATT&CK technique:

| Scenario | Technique ID | Description |
|---|---|---|
| RWX_ALLOC | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Process Injection: Portable Executable Injection |
| RWX_EXEC | [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection |
| HIDE_PROC | [T1564](https://attack.mitre.org/techniques/T1564/) | Hide Artifacts |
| HIDE_COMM | [T1564](https://attack.mitre.org/techniques/T1564/) | Hide Artifacts |
| BYPASS_WX | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools |
| BYPASS_ASLR | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools |
| BPF_VALIDATE | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |
| YARA_SCAN | [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data |

Technique IDs are embedded in terminal output, JSON exports, and CSV reports.


---

## Example Output

```
        ╔═══════════════════════════════════╗
        ║            K-Verify               ║
        ║     Purple Team — Adversarial     ║
        ║          Validation               ║
        ╚═══════════════════════════════════╝

  ══════════════════════════════════════════════════════════════════════════
    RUN SEQUENCE INITIATED
  ══════════════════════════════════════════════════════════════════════════

  [01/08] RWX_ALLOC ......  PASS  [KS:✔  LS:✘]  T1055.001
  [02/08] RWX_EXEC .......  PASS  [KS:✔  LS:✘]  T1055
  [03/08] HIDE_PROC ......  PASS  [KS:✔  LS:✘]  T1564
  [04/08] HIDE_COMM ......  WARN  [KS:✘  LS:✘]  T1564
  [05/08] BYPASS_WX ......  PASS  [KS:✘  LS:✔]  T1562.001
  [06/08] BYPASS_ASLR ....  FAIL  [KS:✘  LS:✔]  T1562.001
  [07/08] BPF_VALIDATE ...  PASS  [KS:✔  LS:✘]  T1059
  [08/08] YARA_SCAN ......  SKIP  [KS:✘  LS:✘]  T1560

  ══════════════════════════════════════════════════════════════════════════
    FINAL ASSESSMENT
  ══════════════════════════════════════════════════════════════════════════

  [█████░░░░░]  4/8  (50%)  adversarial actions succeeded
  [██░░░░░░░░]  2/8  (25%)  detected by K-Scanner
  [█░░░░░░░░░]  1/8  (12%)  detected by LinSpec
  [█████░░░░░]  4/8  (50%)  unmonitored gaps (no KS or LS coverage)

   STATUS:  Purple Team Validation Complete
  ══════════════════════════════════════════════════════════════════════════
```


---

## How It Works

K-Verify runs in three phases.

### Phase 1: Adversarial Execution

Each scenario executes a controlled offensive technique. RWX_ALLOC calls `mmap` with `PROT_READ|PROT_WRITE|PROT_EXEC`. RWX_EXEC writes shellcode (exit(0)) into an RWX region and executes it. HIDE_PROC forks a child then hits it with `prctl(PR_SET_NAME, "[kworker/0:0]")`. HIDE_COMM writes directly to `/proc/self/cmdline`. BYPASS_WX attempts an RWX mmap and checks whether enforcement kicks in. BYPASS_ASLR reads `randomize_va_space`. BPF_VALIDATE checks kernel BTF and BPF JIT hardening state. YARA_SCAN compiles a YARA rule and runs it against test shellcode.

### Phase 2: Detection

For every scenario, K-Verify queries the same kernel interfaces the target Blue Tool would read. On the K-Scanner path, it parses `/proc/[PID]/maps` looking for `rwx` permission entries. On the LinSpec path, it reads `/proc/sys/kernel/*` hardening parameters. Both tools -- K-Scanner and LinSpec -- are reference projects from the SYNTROPY ecosystem. You don't need them installed to run K-Verify. The detection logic for both is baked directly into K-Verify's source code: it reads the same kernel interfaces they would and *predicts* whether they'd fire. If you pass `--live`, it optionally invokes the actual binaries for real validation.

### Phase 3: Correlation

Results come out as a validation matrix. You get to see whether the adversarial action succeeded, whether each Blue Tool would detect it, and the MITRE ATT&CK technique ID. There's a summary with progress bars for adversarial success rate, detection coverage, and unmonitored gaps.

### Detection Gap Analysis

The final assessment includes a metric called **unmonitored gaps** -- scenarios where neither K-Scanner nor LinSpec provides coverage. Those are your highest-risk blind spots.


---

## Build and Run

```bash
# Clone the repository
git clone https://github.com/jeffersoncesarantunes/K-Verify.git
cd K-Verify

# Build the project
make clean && make

# Run the test suite
make test

# Run all scenarios with default terminal output
sudo ./kverify

# Run all scenarios with silent JSON export (no banner, CI/CD ready)
sudo ./kverify --json

# Export results to CSV
sudo ./kverify --csv

# Run a specific module
sudo ./kverify --rwx
sudo ./kverify --hide
sudo ./kverify --bypass
sudo ./kverify --bpf
sudo ./kverify --yara

# Run with live K-Scanner/LinSpec integration
sudo ./kverify --live

# Read-only verification (no adversarial actions)
sudo ./kverify --verify-only

# Clean up any remaining child processes
sudo ./kverify --cleanup
```

### YARA Rule Detection

<span style="color:#7C3AED;font-weight:700;border-bottom:2px solid #7C3AED;">YARA</span> is a pattern-matching engine for malware identification. K-Verify uses it to check whether YARA rules correctly detect shellcode patterns in memory. You'll need it for the `--yara` scenario and the `YARA_SCAN` tests.

```bash
# Install YARA (optional, required for --yara)
sudo pacman -S yara
```

When `--json` is used alone, the tool skips the banner and terminal output entirely and writes only the JSON report file. This is meant for automated pipelines, cron jobs, and CI/CD integration.


---

## Post-Analysis & Report Viewing

Once reports are generated, you can inspect them right from the terminal:

```bash
# View aligned and formatted CSV results (top 15 results)
column -t -s ',' kverify-report.csv | head -n 16

# Quickly inspect the structured JSON output header
cat kverify-report.json | head -n 15
```


---

## Project in Action

Screenshots are reserved for a future visual walkthrough. The images directory contains assets that will be referenced here once the walkthrough is finalized.


---

## Operational Integrity

K-Verify is designed for controlled adversarial testing. All shellcode is benign -- exit(0) only. Child processes are tracked and reaped. The `--cleanup` mode kills any remaining children. `--verify-only` does a read-only assessment. There are no persistent system modifications, no network activity, and no lateral movement. Every action is logged transparently.


---

## Deployment

### Requirements

You'll need a Linux kernel 5.x or newer, gcc, make, and root privileges for /proc access and mmap tests. A UTF-8 compatible terminal helps. Optionally you'll want yara plus yarac for `--yara`, and kscanner plus linspec for `--live`.


---

## Repository Structure

```text
├── .github/workflows/
│   └── ci.yml
├── build/
│   └── obj/
├── docs/
│   ├── ADVERSARIAL_SCENARIOS.md
│   ├── PURPLE_MODEL.md
│   └── VALIDATION_PROTOCOL.md
├── Images/
│   ├── kverify1.png
│   ├── kverify2.png
│   └── kverify3.png
├── include/
│   ├── colors.h
│   ├── kverify.h
│   └── modules.h
├── reports/
├── src/
│   ├── bpf_validate.c
│   ├── bypass.c
│   ├── hide.c
│   ├── main.c
│   ├── rwx.c
│   ├── utils.c
│   ├── verify.c
│   └── yara_scan.c
├── tests/
│   ├── .gitkeep
│   └── test_utils.c
├── .gitignore
├── LICENSE
├── Makefile
└── README.md
```


---

## Tech Stack

The language is C99. Data sources are `/proc`, `mmap`, and `prctl`. The build tool is GNU Make. The test framework is a custom C test harness. Target platforms are Linux Kernel 5.x and 6.x.


---

## Roadmap


- [x] Modular C99 engine with RWX, hide, and bypass modules
- [x] Verification engine cross-referencing K-Scanner and LinSpec
- [x] Color-coded terminal validation matrix
- [x] JSON/CSV structured export with MITRE ATT&CK IDs
- [x] Detection Gap Analysis (unmonitored blind spots)
- [x] Silent JSON mode for CI/CD pipelines
- [x] `--verify-only` read-only assessment mode
- [x] eBPF-based detection validation (`--bpf`)
- [x] YARA rule-based detection pattern matching (`--yara`)
- [x] Live tool integration (`--live`)
- [x] Automated test suite (`make test`)
- [x] CI/CD pipeline (GitHub Actions)
- [ ] Multi-process coordinated attack scenarios


---

## Documentation

[![Docs-Purple](https://img.shields.io/badge/Purple-Model-8A2BE2?style=flat-square\&logo=target\&logoColor=white)](./docs/PURPLE_MODEL.md)
[![Docs-Scenarios](https://img.shields.io/badge/Adversarial-Scenarios-CC0000?style=flat-square\&logo=linux\&logoColor=white)](./docs/ADVERSARIAL_SCENARIOS.md)
[![Docs-Validation](https://img.shields.io/badge/Validation-Protocol-00599C?style=flat-square\&logo=gitbook\&logoColor=white)](./docs/VALIDATION_PROTOCOL.md)


