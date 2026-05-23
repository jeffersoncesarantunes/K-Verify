# Validation Protocol

## Purpose

The validation protocol defines how K-Verify cross-references adversarial actions against the detection capabilities of each Blue Team tool in the SYNTROPY ecosystem.

## Detection Matrix Logic

### K-Scanner Detection

K-Scanner detects RWX memory regions by parsing `/proc/[PID]/maps` and flagging any line whose permission field contains `rwx`.

K-Verify validates this by:

1. After executing an RWX allocation, re-reading `/proc/self/maps`
2. Counting all mappings with `rwx` permissions
3. Distinguishing between anonymous RWX (`[anonymous]`) and file-backed RWX

If any RWX mapping is present, K-Scanner *would* flag it — result: `DETECT`.

**False Positive Consideration:** JIT engines (Python, Node.js, Firefox) legitimately create RWX regions. K-Verify's own allocations are anonymous and non-JIT, so they represent the *suspicious* class K-Scanner is designed to catch.

### LinSpec Detection

LinSpec audits kernel hardening parameters by reading:

- `/proc/sys/kernel/kptr_restrict`
- `/proc/sys/kernel/dmesg_restrict`
- `/proc/sys/kernel/kexec_load_disabled`
- `/proc/sys/kernel/randomize_va_space`

K-Verify validates this by:

1. Reading the same `/proc/sys/` paths
2. Comparing values against the LinSpec hardened baseline
3. Counting parameters that are in a vulnerable state (value = 0)

If 1+ parameter is non-hardened, LinSpec *would* flag it — result: `DETECT`.

## Report Interpretation

### Terminal Output

```
SCENARIO             | EXEC      | K-Scanner | LinSpec | Notes
-------------------- | --------- | --------- | ------- | -----
RWX_ALLOC            | PASS      | DETECT    | MISS    | RWX region at 0x7f...
```

**Purple Team Analysis:**
- RWX_ALLOC execution succeeded (PASS) — the kernel allowed RWX memory
- K-Scanner catches it (DETECT) — defense is working
- Improvement: Red team cannot hide RWX allocations from K-Scanner

### JSON Output

```json
{
  "scenario": "RWX_ALLOC",
  "execution_result": "PASS",
  "detection": {
    "kscanner": true,
    "linspec": false
  }
}
```

## Scenario-Specific Validation Rules

| Scenario | K-Scanner | LinSpec |
|---|---|---|
| RWX_ALLOC | /proc/self/maps rwx count | Not checked |
| RWX_EXEC | /proc/self/maps rwx count | Not checked |
| HIDE_PROC | /proc/child/comm match | Not checked |
| HIDE_COMM | /proc/self/cmdline | Not checked |
| BYPASS_WX | Not checked | hardening parameters |
| BYPASS_ASLR | Not checked | randomize_va_space |

## Limitations

- **Synthetic Detection:** K-Verify detects what K-Scanner *would* detect, not what K-Scanner actually detects. True validation requires running K-Scanner in parallel.
- **Single-Host Scope:** No network-based attack or detection validation.
- **No Persistence:** All adversarial actions are ephemeral — no persistence mechanism is tested.
