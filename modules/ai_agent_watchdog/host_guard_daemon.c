#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <dirent.h>
#include <sys/inotify.h>

extern int watchdog_freeze_rogue_agents(void);

static void log_alert(const char *msg) {
    char *lp = calloc(1, 256);
    snprintf(lp, 256, "%s/.zero_host_guard.log", getenv("HOME"));
    FILE *f = fopen(lp, "a");
    if (f) { fprintf(f, "[%ld] ТРЕВОГА ХОСТА: %s\n", (long)time(NULL), msg); fclose(f); }
    free(lp);
}

int main(int argc, char **argv) {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) return 1;
    for (int i = 1; i < argc; i++) {
        inotify_add_watch(fd, *(argv + i), IN_DELETE | IN_MOVED_FROM | IN_CREATE);
    }
    log_alert("Сторож хоста ZEROMANI запущен и взял каталоги под охрану ядра.");
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    uint8_t *buf = calloc(1, 4096);
    while (poll(&pfd, 1, -1) >= 0) {
        ssize_t len = read(fd, buf, 4096);
        size_t pos = 0;
        while (len > 0 && pos + sizeof(struct inotify_event) <= (size_t)len) {
            struct inotify_event *ev = (struct inotify_event *)(buf + pos);
            if (ev->len > 0 && ((ev->mask & (IN_DELETE | IN_MOVED_FROM)) || strncmp(ev->name, ".cline", 6) == 0)) {
                int fz = watchdog_freeze_rogue_agents();
                char *msg = calloc(1, 256);
                snprintf(msg, 256, "Перехвачено действие над '%s' (заморожено агентов: %d)", ev->name, fz);
                log_alert(msg);
                free(msg);
            }
            pos += sizeof(struct inotify_event) + ev->len;
        }
    }
    return 0;
}
