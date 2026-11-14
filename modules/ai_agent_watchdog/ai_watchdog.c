#define _GNU_SOURCE
#include "../module_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/inotify.h>

static int inotify_fd = -1;
static uint64_t blocked_actions = 0;

static int is_rogue_agent_file(const char *name) {
    if (!name) return 0;
    if (strncmp(name, ".cline", 6) == 0) return 1;
    if (strncmp(name, ".cursor", 7) == 0) return 1;
    if (strncmp(name, ".aider", 6) == 0) return 1;
    return 0;
}

int watchdog_freeze_rogue_agents(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int frozen = 0;
    char *path = calloc(1, 64);
    char *cmd  = calloc(1, 256);
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        pid_t pid = (pid_t)atoi(ent->d_name);
        if (pid <= 1 || pid == getpid()) continue;
        snprintf(path, 64, "/proc/%d/cmdline", pid);
        FILE *f = fopen(path, "rb");
        if (!f) continue;
        size_t n = fread(cmd, 1, 255, f);
        fclose(f);
        for (size_t i = 0; i < n; i++) if (*(cmd + i) == '\0') *(cmd + i) = ' ';
        *(cmd + n) = '\0';
        if (strstr(cmd, "cline") || strstr(cmd, "aider") || strstr(cmd, "auto-approve")) {
            if (kill(pid, SIGSTOP) == 0) frozen++;
        }
    }
    free(path); free(cmd); closedir(d);
    return frozen;
}

static int wd_init(uint64_t seed) {
    (void)seed;
    inotify_fd = inotify_init1(IN_NONBLOCK);
    blocked_actions = 0;
    return (inotify_fd >= 0) ? 0 : -1;
}

int watchdog_watch_dir(const char *dir_path) {
    if (inotify_fd < 0) return -1;
    return inotify_add_watch(inotify_fd, dir_path, IN_DELETE | IN_MOVED_FROM | IN_CREATE | IN_MODIFY);
}

size_t watchdog_poll_events(int *out_frozen_pids) {
    if (inotify_fd < 0) return 0;
    uint8_t *buf = calloc(1, 4096);
    ssize_t len = read(inotify_fd, buf, 4096);
    size_t alerts = 0;
    if (len > 0) {
        size_t pos = 0;
        while (pos + sizeof(struct inotify_event) <= (size_t)len) {
            struct inotify_event *ev = (struct inotify_event *)(buf + pos);
            if (ev->len > 0) {
                if ((ev->mask & (IN_DELETE | IN_MOVED_FROM)) || is_rogue_agent_file(ev->name)) {
                    alerts++;
                    blocked_actions++;
                }
            }
            pos += sizeof(struct inotify_event) + ev->len;
        }
    }
    free(buf);
    if (alerts > 0) {
        int fz = watchdog_freeze_rogue_agents();
        if (out_frozen_pids) *out_frozen_pids = fz;
    }
    return alerts;
}

static size_t wd_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)buf; (void)len; (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    int frozen = 0;
    return watchdog_poll_events(&frozen);
}

static void wd_shutdown(void) {
    if (inotify_fd >= 0) { close(inotify_fd); inotify_fd = -1; }
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 6,
    .name = "ai_agent_process_watchdog", .init = wd_init,
    .process_frame = wd_process_frame, .shutdown = wd_shutdown
};
