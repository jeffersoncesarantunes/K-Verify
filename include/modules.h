#ifndef MODULES_H
#define MODULES_H

#include "kverify.h"

void *rwx_allocate(size_t size, ScenarioResult *result);
int rwx_execute(void *addr, size_t size, const unsigned char *shellcode,
                size_t sc_len, ScenarioResult *result);
void rwx_release(void *addr, size_t size);

pid_t hide_fork_masquerade(const char *new_name, ScenarioResult *result);
int hide_argv_masquerade(const char *new_name, ScenarioResult *result);
TestResult bypass_wx_check(ScenarioResult *result);
TestResult bypass_aslr_assess(ScenarioResult *result);

TestResult bpf_validate(ScenarioResult *result);
TestResult yara_scan(ScenarioResult *result);

int verify_kscanner_rwx(ScenarioResult *result);
int verify_linspec_hardening(ScenarioResult *result);
int verify_live_kscanner(ScenarioResult *result);
int verify_live_linspec(ScenarioResult *result);
int verify_full(ScenarioResult *results, int count);

void cleanup_tracked_children(void);

#endif
