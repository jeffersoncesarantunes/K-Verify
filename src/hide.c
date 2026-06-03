#include "../include/kverify.h"
#include "../include/modules.h"

pid_t hide_fork_masquerade(const char *new_name, ScenarioResult *result)
{
    if (!new_name) new_name = "[kworker]";

    pid_t child = fork();
    if (child == -1) {
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "fork failed: %s", strerror(errno));
        return -1;
    }

    if (child == 0) {
        if (prctl(PR_SET_NAME, new_name) == -1)
            _exit(1);

        char proc_path[MAX_PATH_LEN];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", getpid());
        int fd = open(proc_path, O_WRONLY);
        if (fd >= 0) {
            ssize_t ret = write(fd, new_name, strlen(new_name));
            (void)ret;
            close(fd);
        }

        pause();
        _exit(0);
    }

    char child_comm[MAX_NAME_LEN];
    char comm_path[MAX_PATH_LEN];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", child);

    usleep(100000);

    if (read_proc_line(comm_path, child_comm, sizeof(child_comm)) == 0) {
        if (strcmp(child_comm, new_name) == 0) {
            result->execution_result = RESULT_PASS;
            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "Child %d masqueraded as '%s'", child, child_comm);
        } else {
            result->execution_result = RESULT_WARN;
            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "Child %d comm='%s' (expected '%s')", child, child_comm, new_name);
        }
    } else {
        result->execution_result = RESULT_FAIL;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not read /proc/%d/comm", child);
    }

    result->detection.kscanner_detected = result->execution_result == RESULT_PASS;
    return child;
}

int hide_argv_masquerade(const char *new_name, ScenarioResult *result)
{
    if (!new_name) new_name = "[kworker]";

#ifndef HIDE_ARGV_SIZE
#define HIDE_ARGV_SIZE 256
#endif

    static char fake_name[HIDE_ARGV_SIZE];
    snprintf(fake_name, sizeof(fake_name), "%s", new_name);

    int fd = open("/proc/self/cmdline", O_WRONLY);
    if (fd >= 0) {
        ssize_t ret = write(fd, fake_name, strlen(fake_name) + 1);
        (void)ret;
        close(fd);
    }

    char actual[MAX_LINE_LEN];
    if (read_proc_line("/proc/self/cmdline", actual, sizeof(actual)) == 0) {
        trim_newline(actual);
        if (strstr(actual, new_name) || strstr(actual, fake_name)) {
            result->execution_result = RESULT_PASS;
            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "argv[0] masqueraded as '%s'", fake_name);
        } else {
            result->execution_result = RESULT_WARN;
            char truncated[200];
            snprintf(truncated, sizeof(truncated), "%.190s", actual);
            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "argv unchanged: '%s'", truncated);
        }
    } else {
        result->execution_result = RESULT_SKIP;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Could not read /proc/self/cmdline");
    }

    result->detection.kscanner_detected = 0;
    return 0;
}

pid_t hide_suspended_child(ScenarioResult *result)
{
    pid_t child = fork();
    if (child == -1) {
        result->execution_result = RESULT_ERROR;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "fork failed: %s", strerror(errno));
        return -1;
    }

    if (child == 0) {
        raise(SIGSTOP);
        _exit(0);
    }

    usleep(50000);

    char proc_path[MAX_PATH_LEN];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/status", child);

    if (path_exists(proc_path)) {
        char status_buf[MAX_LINE_LEN];
        if (read_proc_line(proc_path, status_buf, sizeof(status_buf)) == 0) {
            result->execution_result = RESULT_PASS;
            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "Suspended child %d visible in /proc", child);
        } else {
            result->execution_result = RESULT_WARN;
            snprintf(result->detection.notes, sizeof(result->detection.notes),
                     "Child %d created but status unreadable", child);
        }
    } else {
        result->execution_result = RESULT_FAIL;
        snprintf(result->detection.notes, sizeof(result->detection.notes),
                 "Child %d not found in /proc (hidden?)", child);
    }

    result->detection.kscanner_detected = 1;
    return child;
}
