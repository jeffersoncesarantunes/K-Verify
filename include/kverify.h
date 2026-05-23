#ifndef KVERIFY_H
#define KVERIFY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include "colors.h"

#define MAX_SCENARIOS     16
#define MAX_NAME_LEN      64
#define MAX_PATH_LEN      256
#define MAX_LINE_LEN      1024
#define SHELLCODE_SIZE    128

typedef enum {
    RESULT_PASS = 0,
    RESULT_FAIL,
    RESULT_WARN,
    RESULT_SKIP,
    RESULT_ERROR
} TestResult;

typedef enum {
    SCENARIO_RWX_ALLOC,
    SCENARIO_RWX_EXEC,
    SCENARIO_HIDE_PROC,
    SCENARIO_HIDE_COMM,
    SCENARIO_BYPASS_WX,
    SCENARIO_BYPASS_ASLR,
    SCENARIO_COUNT
} ScenarioType;

extern const char *scenario_names[SCENARIO_COUNT];
extern const char *mitre_ids[SCENARIO_COUNT];

typedef struct {
    int kscanner_detected;
    int linspec_detected;
    char notes[MAX_PATH_LEN];
} DetectionResult;

typedef struct {
    ScenarioType type;
    TestResult execution_result;
    DetectionResult detection;
} ScenarioResult;

typedef enum {
    EXPORT_TERMINAL = 0,
    EXPORT_JSON,
    EXPORT_CSV
} ExportFormat;

void trim_newline(char *s);
int read_proc_line(const char *path, char *buf, size_t size);
int path_exists(const char *path);

void export_results_terminal(ScenarioResult *results, int count);
void export_results_compact(ScenarioResult *results, int count,
                            const char notes[][MAX_PATH_LEN]);
void export_results_json(ScenarioResult *results, int count, const char *filename);
void export_results_csv(ScenarioResult *results, int count, const char *filename);

#endif
