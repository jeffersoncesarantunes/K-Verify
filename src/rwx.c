#include "../include/kverify.h"
#include "../include/modules.h"

void *rwx_allocate(size_t size, ScenarioResult *result)
{
    if (size == 0) size = 4096;

    void *addr = mmap(NULL, size,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (addr == MAP_FAILED) {
        result->execution_result = RESULT_FAIL;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "mmap RWX failed: %s", strerror(errno));
        return NULL;
    }

    result->execution_result = RESULT_PASS;
    snprintf(result->detection.notes, sizeof(result->detection.notes),
             "RWX region at %p (%zu bytes)", addr, size);

    result->detection.kscanner_detected = 1;

    return addr;
}

int rwx_execute(void *addr, size_t size, const unsigned char *shellcode,
                size_t sc_len, ScenarioResult *result)
{
    if (!addr || !shellcode || sc_len == 0) {
        result->execution_result = RESULT_ERROR;
        return -1;
    }

    if (sc_len > size) sc_len = size;

    memcpy(addr, shellcode, sc_len);

    __builtin___clear_cache(addr, (char *)addr + sc_len);

    volatile void *fn_addr = addr;

    pid_t child = fork();
    if (child == -1) {
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "fork failed: %s", strerror(errno));
        return -1;
    }

    if (child == 0) {
        void (*sc)(void) = (void (*)(void))fn_addr;
        sc();
        _exit(0);
    }

    int status;
    waitpid(child, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        result->execution_result = RESULT_PASS;
        result->detection.kscanner_detected = 1;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Shellcode executed at %p (pid %d)", addr, child);
    } else {
        result->execution_result = RESULT_WARN;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Shellcode exit status: %d", WEXITSTATUS(status));
    }

    return 0;
}

void rwx_release(void *addr, size_t size)
{
    if (addr && size > 0)
        munmap(addr, size);
}
