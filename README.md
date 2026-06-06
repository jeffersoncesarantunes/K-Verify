# 🐧 K-Verify

Purple Team adversarial validation suite for the SYNTROPY forensic ecosystem.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-A8B9CC?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-006400?style=flat-square)](#-roadmap)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=githubactions)](.github/workflows/ci.yml)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Purple%20Team%20%7C%20Adversarial%20Validation-8A2BE2?style=flat-square)](#-overview)

---

## ● Etymology & Origin

The name **K-Verify** derives from the Linux **Kernel** — the foundational interface that underpins all validation logic. The "K" references the Kernel in the same spirit as **K-Scanner**, its sister project in the SYNTROPY ecosystem. Unlike a scanner that enumerates state, K-Verify *verifies*: it actively tests whether detection mechanisms correctly identify adversarial behavior on a live system.

---

## ● Overview

K-Verify is a Purple Team adversarial validation tool designed to stress-test the detection capabilities of the SYNTROPY forensic ecosystem — **K-Scanner** and **LinSpec**.

It executes controlled adversarial actions on a live Linux system and then cross-references each action against the kernel interfaces that the Blue Team tools use for detection. Each scenario is mapped to a **MITRE ATT&CK** technique, and the final assessment includes a **Detection Gap Analysis** that highlights blind spots where no tool provides coverage.

**Core Validation Areas:**

* **RWX Memory Detection:** Allocates writable+executable memory and verifies K-Scanner detection
* **Process Masquerading:** Forks and renames processes to test /proc enumeration accuracy
* **Mitigation Bypass:** Attempts W^X and ASLR bypass and validates LinSpec auditing
* **eBPF Telemetry Validation:** Checks kernel BTF and BPF JIT state for eBPF readiness
* **YARA Rule Detection:** Validates YARA pattern matching against known shellcode signatures
* **Live Tool Integration:** Optionally invokes real K-Scanner/LinSpec binaries for actual detection testing
* **Detection Gap Analysis:** Counts scenarios with zero detection coverage (neither K-Scanner nor LinSpec)
* **MITRE ATT&CK Correlation:** Each adversarial technique mapped to its MITRE technique ID

---

## ● Features

* Eight adversarial scenarios mapped to MITRE ATT&CK technique IDs
* eBPF telemetry validation (`--bpf`) — detects kernel BTF and BPF JIT readiness
* YARA rule detection test (`--yara`) — validates YARA engine with known shellcode patterns
* Live tool integration (`--live`) — invokes actual K-Scanner/LinSpec binaries
* Automated verification against K-Scanner and LinSpec detection logic
* Purple Team validation matrix with color-coded terminal output
* **Detection Gap Analysis** — identifies blind spots with no tool coverage
* **MITRE ATT&CK mapping** — technique IDs in terminal, JSON, and CSV output
* **Silent JSON mode** (`--json`) — suppress banner output for CI/CD pipelines
* Structured export (JSON/CSV) for integration into reporting pipelines
* Modular C99 engine — each scenario is an independent module
* Automated unit test suite with `make test`
* CI/CD pipeline via GitHub Actions
* Read-only verification phase that assesses system state without executing attacks
* Child process lifecycle management with cleanup mode

---

## ● MITRE ATT&CK Mapping

Each scenario is correlated with a real-world MITRE ATT&CK technique:

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

Technique IDs are displayed in the terminal output, embedded in JSON export, and included in CSV reports.

---

## ● Example Output

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

  [██████░░░░]  4/8  (50%)  adversarial actions succeeded
  [██░░░░░░░░]  2/8  (25%)  detected by K-Scanner
  [█░░░░░░░░░]  1/8  (12%)  detected by LinSpec
  [██████░░░░]  4/8  (50%)  unmonitored gaps (no KS or LS coverage)

   STATUS:  Purple Team Validation Complete
  ══════════════════════════════════════════════════════════════════════════
```

---

## ● How It Works

K-Verify operates in three phases:

### Phase 1: Adversarial Execution

Each scenario executes a controlled offensive technique:

* **RWX_ALLOC:** `mmap` with `PROT_READ|PROT_WRITE|PROT_EXEC`
* **RWX_EXEC:** Shellcode (exit(0)) written and executed in RWX region
* **HIDE_PROC:** Fork + `prctl(PR_SET_NAME, "[kworker/0:0]")`
* **HIDE_COMM:** Direct write to `/proc/self/cmdline`
* **BYPASS_WX:** Attempt RWX mmap, test enforcement
* **BYPASS_ASLR:** Read `randomize_va_space`
* **BPF_VALIDATE:** Check kernel BTF and BPF JIT hardening state
* **YARA_SCAN:** Compile and run YARA rule against test shellcode

### Phase 2: Detection

For each scenario, K-Verify queries the kernel interfaces that the target Blue Tool uses:

* **K-Scanner path:** Parses `/proc/[PID]/maps` for `rwx` permission entries
* **LinSpec path:** Reads `/proc/sys/kernel/*` hardening parameters

**Note:** K-Scanner and LinSpec are reference tools from the SYNTROPY forensic ecosystem. They are **not required** to run K-Verify. The detection logic for both tools is embedded directly in K-Verify's own source code — it reads the same kernel interfaces they would use and *predicts* whether detection would occur. When `--live` is passed, K-Verify optionally invokes the actual K-Scanner and LinSpec binaries for real validation.

### Phase 3: Correlation

Results are presented as a **validation matrix** showing:

* Whether the adversarial action succeeded
* Whether each Blue Tool would detect it
* The MITRE ATT&CK technique ID
* A summary with progress bars for adversarial success, detection coverage, and **unmonitored gaps**

### Detection Gap Analysis

The final assessment includes a dedicated metric: **unmonitored gaps** — scenarios where neither K-Scanner nor LinSpec provides detection coverage. These represent the highest-risk blind spots in your detection posture.

---

## ● Build and Run

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

[YARA](https://virustotal.github.io/yara/) is a pattern-matching engine for malware identification. K-Verify uses it to validate that YARA rules correctly detect shellcode patterns in memory. Required for the `--yara` scenario and `YARA_SCAN` tests.

```bash
# Install YARA (optional, required for --yara)
# Arch Linux
sudo pacman -S yara
# Debian/Ubuntu
sudo apt install yara
```

**JSON silent mode:** When `--json` is used alone, the tool skips the banner and terminal output entirely, writing only the JSON report file. This is designed for automated pipelines, cron jobs, and CI/CD integration.

---

## ● Post-Analysis & Report Viewing

After generating the reports, you can quickly inspect them directly from the terminal using standard Linux utilities:

```bash
# View aligned and formatted CSV results (top 15 results)
column -t -s ',' kverify-report.csv | head -n 16

# Quickly inspect the structured JSON output header
cat kverify-report.json | head -n 15
```

---

## ● Operational Integrity

K-Verify is designed for controlled adversarial testing:

* All shellcode is benign — `exit(0)` only
* Child processes are tracked and reaped
* `--cleanup` mode kills remaining children
* `--verify-only` performs read-only assessment
* No persistent system modifications
* No network activity or lateral movement
* Transparent logging of every action

---

## ● Deployment

### Requirements

* Linux Kernel 5.x or newer
* gcc
* make
* Root privileges (for /proc access and mmap tests)
* UTF-8 compatible terminal
* yara + yarac (optional, for `--yara`)
* kscanner (optional, for `--live`)
* linspec (optional, for `--live`)

---

## ● Repository Structure

```text
├── .github/workflows/
│   └── ci.yml                     CI/CD pipeline
├── build/
│   └── obj/
├── docs/
│   ├── ADVERSARIAL_SCENARIOS.md
│   ├── PURPLE_MODEL.md
│   └── VALIDATION_PROTOCOL.md
├── Imagens/
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

## ● Tech Stack

* **Language:** C99
* **Data Sources:** `/proc`, `mmap`, `prctl`
* **Build Tool:** GNU Make
* **Test Framework:** Custom C test harness
* **Target Platforms:** Linux Kernel 5.x / 6.x

---

## ● Roadmap

* [x] Modular C99 engine with RWX, hide, and bypass modules
* [x] Verification engine cross-referencing K-Scanner and LinSpec
* [x] Color-coded terminal validation matrix
* [x] JSON/CSV structured export with MITRE ATT&CK IDs
* [x] Detection Gap Analysis (unmonitored blind spots)
* [x] Silent JSON mode for CI/CD pipelines
* [x] `--verify-only` read-only assessment mode
* [x] eBPF-based detection validation (`--bpf`)
* [x] YARA rule-based detection pattern matching (`--yara`)
* [x] Live tool integration (`--live`)
* [x] Automated test suite (`make test`)
* [x] CI/CD pipeline (GitHub Actions)
* [ ] Multi-process coordinated attack scenarios

---

## ● Documentation

[![Docs-Purple](https://img.shields.io/badge/Purple-Model-8A2BE2?style=flat-square\&logo=target\&logoColor=white)](./docs/PURPLE_MODEL.md)
[![Docs-Scenarios](https://img.shields.io/badge/Adversarial-Scenarios-CC0000?style=flat-square\&logo=linux\&logoColor=white)](./docs/ADVERSARIAL_SCENARIOS.md)
[![Docs-Validation](https://img.shields.io/badge/Validation-Protocol-00599C?style=flat-square\&logo=gitbook\&logoColor=white)](./docs/VALIDATION_PROTOCOL.md)

---

## ● License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square\&logo=opensourceinitiative\&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License.*
