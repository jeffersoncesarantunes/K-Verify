# Validation Protocol

## Purpose

The validation protocol defines how K-Verify cross-references adversarial actions against each Blue Team tool in the SYNTROPY ecosystem and works out whether the detection layer actually catches them.

## Detection Matrix Logic

### K-Scanner Detection

K-Scanner detects RWX memory regions by walking `/proc/[PID]/maps` and flagging any line where the permission field contains `rwx`. K-Verify validates this the same way: after executing an RWX allocation, it re-reads `/proc/self/maps`, counts every mapping with `rwx` permissions, and distinguishes between anonymous RWX (`[anonymous]`) and file-backed RWX. If any RWX mapping is present, K-Scanner *would* flag it and the result comes back as `DETECT`.

There's a false positive angle worth calling out. JIT engines from Python, Node.js, and Firefox legitimately create RWX regions. K-Verify's allocations are anonymous and non-JIT, which puts them in the *suspicious* category K-Scanner is specifically designed to catch.

### LinSpec Detection

LinSpec audits kernel hardening parameters by reading a handful of `/proc/sys/` paths -- `kptr_restrict`, `dmesg_restrict`, `kexec_load_disabled`, and `randomize_va_space`. K-Verify reads the same files, compares the values against LinSpec's hardened baseline, and counts how many parameters are sitting in a vulnerable state (value = 0). If at least one parameter is non-hardened, LinSpec *would* flag it and the result is `DETECT`.

## Report Interpretation

### Terminal Output

```
SCENARIO             | EXEC      | K-Scanner | LinSpec | Notes
-------------------- | --------- | --------- | ------- | -----
RWX_ALLOC            | PASS      | DETECT    | MISS    | RWX region at 0x7f...
```

On the Purple Team side, RWX_ALLOC execution succeeded (PASS) which means the kernel allowed RWX memory. K-Scanner catches it (DETECT), so that defense is working. The takeaway is that a red team can't hide RWX allocations from K-Scanner here.

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
| BPF_VALIDATE | BTF + bpf_jit_harden sysctl | Not checked |
| YARA_SCAN | YARA rule match result | Not checked |

## Limitations

This is synthetic detection -- K-Verify detects what K-Scanner *would* detect, not what K-Scanner actually detects at runtime. True validation means running K-Scanner in parallel. The `--live` flag partially addresses this by optionally invoking real K-Scanner and LinSpec binaries when they're in $PATH. Everything runs on a single host, so there's no network-based attack or detection validation. All adversarial actions are ephemeral, meaning no persistence mechanism gets tested.
