#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <stdarg.h>

// ========= 전역 변수 =========
static int base_fd = -1;
static FILE *log_fp = NULL;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

// ========= 대량 삭제 차단 =========
#define UNLINK_WINDOW_SEC      10
#define MAX_UNLINK_PER_WINDOW  5
static time_t rl_window_start = 0;
static int rl_unlink_count = 0;

static int unlink_rate_limit_exceeded(int *out_count_in_window) {
    time_t now = time(NULL);
    if (rl_window_start == 0 || difftime(now, rl_window_start) >= UNLINK_WINDOW_SEC) {
        rl_window_start = now;
        rl_unlink_count = 0;
    }
    rl_unlink_count++;
    if (out_count_in_window) *out_count_in_window = rl_unlink_count;
    return (rl_unlink_count > MAX_UNLINK_PER_WINDOW);
}

// ========= 경로 처리 =========
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/') path++;
        strncpy(relpath, path, PATH_MAX);
        relpath[PATH_MAX - 1] = '\0';
    }
}

// ========= 로그 함수 =========
static void log_line(const char *action, const char *path, const char *result,
                     const char *reason, const char *extra_fmt, ...) {
    char ts[64];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

    struct fuse_context *fc = fuse_get_context();
    uid_t uid = fc ? fc->uid : (uid_t)-1;
    pid_t pid = fc ? fc->pid : (pid_t)-1;

    char extra[256] = {0};
    if (extra_fmt && extra_fmt[0]) {
        va_list ap;
        va_start(ap, extra_fmt);
        vsnprintf(extra, sizeof(extra), extra_fmt, ap);
        va_end(ap);
    }

    pthread_mutex_lock(&log_lock);
    if (log_fp) {
        fprintf(log_fp,
                "ts=%s uid=%d pid=%d action=%s path=\"%s\" result=%s reason=\"%s\"%s%s\n",
                ts, (int)uid, (int)pid, action, path, result,
                reason ? reason : "",
                extra[0] ? " extra=\"" : "",
                extra[0] ? extra : "");
        if (extra[0]) fprintf(log_fp, "\"");
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
    pthread_mutex_unlock(&log_lock);
}

// ========= FUSE 콜백 =========
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    if (fstatat(base_fd, rel, stbuf, AT_SYMLINK_NOFOLLOW) == -1) return -errno;
    return 0;
}

static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    int fd = openat(base_fd, rel, fi->flags);
    if (fd == -1) return -errno;
    fi->fh = fd;
    return 0;
}

static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;
    struct stat st;
    if (fstat(fi->fh, &st) == -1) return -errno;

    off_t real_size = st.st_size;
    if (offset >= real_size) {
        log_line("READ", path, "ALLOW_FAKE", "policy:mask", "size=0 offset=%ld", (long)offset);
        return 0;
    }

    size_t to_read = size;
    if ((off_t)to_read > real_size - offset)
        to_read = (size_t)(real_size - offset);

    const char *pattern = "FAKE_DATA_BLOCK_0123456789\n";
    size_t plen = strlen(pattern);
    size_t pos = (size_t)(offset % plen);
    size_t filled = 0;
    while (filled < to_read) {
        size_t chunk = plen - pos;
        if (chunk > to_read - filled) chunk = to_read - filled;
        memcpy(buf + filled, pattern + pos, chunk);
        filled += chunk;
        pos = 0;
    }

    if (offset == 0)
        log_line("READ", path, "ALLOW_FAKE", "policy:mask", "size=%zu offset=%ld", to_read, (long)offset);
    return (int)to_read;
}

static int myfs_unlink(const char *path) {
    int count_in_window = 0;
    int exceeded = unlink_rate_limit_exceeded(&count_in_window);
    if (exceeded) {
        log_line("UNLINK", path, "BLOCK", "rate-limit",
                 "window=%ds max=%d count=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count_in_window);
        return -EPERM;
    } else {
        log_line("UNLINK", path, "DENY", "policy:protect",
                 "window=%ds max=%d count=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count_in_window);
        return -EACCES;
    }
}

static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    int fd = openat(base_fd, rel, fi->flags | O_CREAT, mode);
    if (fd == -1) return -errno;
    fi->fh = fd;
    log_line("CREATE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    ssize_t res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) res = -errno;
    log_line("WRITE", path, "ALLOW", "policy:basic", "size=%zu offset=%ld", size, (long)offset);
    return (int)res;
}

static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    log_line("RELEASE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// ========= main 함수 =========
int main(int argc, char *argv[]) {
    // ✅ FUSE 옵션으로 -f 추가 (항상 포그라운드 모드)
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    if (fuse_opt_add_arg(&args, argv[0]) == -1) return -1;
    if (fuse_opt_add_arg(&args, "-f") == -1) return -1;

    // ✅ 고정 마운트 지점: $HOME/workspace/target
    const char *home = getenv("HOME");
    char mountpoint[PATH_MAX];
    snprintf(mountpoint, sizeof(mountpoint), "%s/workspace/target", home ? home : "/tmp");

    struct stat st;
    if (stat(mountpoint, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "❌ Mountpoint not found: %s\n", mountpoint);
        return -1;
    }

    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open mountpoint");
        return -1;
    }

    // ✅ 로그 파일은 $HOME/myfs_log.txt
    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/myfs_log.txt", home ? home : "/tmp");
    log_fp = fopen(log_path, "a");
    if (!log_fp) perror("fopen log");

    log_line("START", "/", "ALLOW", "boot", "mountpoint=\"%s\"", mountpoint);

    // ✅ 마운트 경로를 FUSE 인자에 추가해야 함 (중요!)
    if (fuse_opt_add_arg(&args, mountpoint) == -1) {
        fprintf(stderr, "Failed to add mountpoint to fuse args\n");
        return -1;
    }

    // ✅ FUSE 실행 (myfs_oper 구조체 전달)
    static const struct fuse_operations myfs_oper = {
        .getattr = myfs_getattr,
        .open    = myfs_open,
        .read    = myfs_read,
        .unlink  = myfs_unlink,
	.create  = myfs_create,
	.write   = myfs_write,
	.release = myfs_release
    };

    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    log_line("STOP", "/", "ALLOW", "shutdown", NULL);

    if (log_fp) fclose(log_fp);
    close(base_fd);
    fuse_opt_free_args(&args);
    return ret;
}
