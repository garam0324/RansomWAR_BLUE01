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

// 전역 변수
static int base_fd = -1; // base 디렉터리
static FILE *log_fp = NULL; // 로그 파일 스트림
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER; // 로그 동시성 제어용 mutex

// --- 악성 행위 탐지 (PID 기반) ---
#define UNLINK_WINDOW_SEC     10 // 행위 탐지 시간 윈도우 (초)
#define MAX_UNLINK_PER_WINDOW 2  // 윈도우 내 최대 허용 '삭제' 수
#define MAX_TRACKED_PIDS    1024 // 추적할 최대 PID 개수

// PID별 상태 추적 구조체
typedef struct {
    pid_t pid;                 // 프로세스 ID
    time_t window_start;       // 현재 윈도우 시작 시간
    int unlink_count;          // 현 윈도우 내 '삭제' 횟수
    int is_malicious;        // '악성'으로 플래그되었는지 여부 (Sticky)
} PidStats;

static PidStats g_pid_stats[MAX_TRACKED_PIDS]; // PID 추적 테이블
static pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER; // 추적 테이블 보호용 mutex

/**
 * @brief 현재 fuse context의 PID에 대한 통계 객체를 반환합니다.
 * 필요시 새 객체를 생성하거나 오래된 객체를 재활용합니다.
 */
static PidStats* get_current_pid_stats() {
    struct fuse_context *fc = fuse_get_context();
    if (fc == NULL) return NULL;
    pid_t current_pid = fc->pid;

    pthread_mutex_lock(&g_stats_lock);

    PidStats *found = NULL;
    PidStats *empty_slot = NULL;
    time_t now = time(NULL);

    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        // 1. 오래된 항목(윈도우 5배수)은 정리 (Garbage Collection)
        if (g_pid_stats[i].pid != 0 && difftime(now, g_pid_stats[i].window_start) > (UNLINK_WINDOW_SEC * 5)) {
            memset(&g_pid_stats[i], 0, sizeof(PidStats));
        }

        // 2. 현재 PID와 일치하는 항목 검색
        if (g_pid_stats[i].pid == current_pid) {
            found = &g_pid_stats[i];
            break;
        }
        // 3. 비어있는 슬롯 저장
        if (g_pid_stats[i].pid == 0 && empty_slot == NULL) {
            empty_slot = &g_pid_stats[i];
        }
    }

    if (found) {
        // 4. 찾았지만 윈도우가 만료되었으면 리셋
        if (difftime(now, found->window_start) >= UNLINK_WINDOW_SEC) {
            found->window_start = now;
            found->unlink_count = 0;
            // is_malicious 플래그는 리셋하지 않음 (한 번 악성이면 계속 악성)
        }
        pthread_mutex_unlock(&g_stats_lock);
        return found;
    }

    if (empty_slot) {
        // 5. 새 항목 생성
        empty_slot->pid = current_pid;
        empty_slot->window_start = now;
        empty_slot->unlink_count = 0;
        empty_slot->is_malicious = 0;
        pthread_mutex_unlock(&g_stats_lock);
        return empty_slot;
    }

    pthread_mutex_unlock(&g_stats_lock);
    return NULL; // 테이블 꽉 참
}
// --- 악성 행위 탐지 끝 ---


// 경로 처리
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/') path++;
        strncpy(relpath, path, PATH_MAX);
        relpath[PATH_MAX - 1] = '\0'; // NULL 보장
    }
}

// 로그 함수 (원본 코드 버그 수정)
static void log_line(const char *action, const char *path, const char *result,
                     const char *reason, const char *extra_fmt, ...) {
    char ts[64]; // 로컬 시각
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

    uid_t uid;
    pid_t pid;
    struct fuse_context *fc = fuse_get_context();
    if (fc != NULL) {
        uid = fc->uid;
        pid = fc->pid;
    }
    else {
        uid = (uid_t)-1;
        pid = (pid_t)-1;
    }

    char extra[256] = {0};
    if (extra_fmt && extra_fmt[0]) {
        va_list ap;
        va_start(ap, extra_fmt);
        vsnprintf(extra, sizeof(extra), extra_fmt, ap);
        va_end(ap);
    }

    pthread_mutex_lock(&log_lock); // 스레드 안전하게 log_lock으로 보호
    if (log_fp) {
        fprintf(log_fp,
                "ts=%s uid=%d pid=%d action=%s path=\"%s\" result=%s ",
                ts, (int)uid, (int)pid, action, path, result);
        
        if (reason != NULL) {
            fprintf(log_fp, "reason=\"%s\"", reason);
        } else {
            fprintf(log_fp, "reason=\"\"");
        }

        if (extra[0] != '\0') {
            fprintf(log_fp, " extra=\"%s\"", extra);
        }

        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
    pthread_mutex_unlock(&log_lock);
}

// ========= FUSE 콜백 =========
// getattr
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    if (fstatat(base_fd, rel, stbuf, AT_SYMLINK_NOFOLLOW) == -1) return -errno;
    return 0;
}

// open
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    int fd = openat(base_fd, rel, fi->flags);
    if (fd == -1) return -errno;
    fi->fh = fd;
    return 0;
}

// read (*** 악성 PID 탐지 로직 포함 ***)
static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    
    // ** 1. 현재 PID의 악성 상태 조회 **
    PidStats *stats = get_current_pid_stats();
    pid_t pid = (stats != NULL) ? stats->pid : (pid_t)-1;

    // ** 2. 악성 PID로 플래그된 경우, FAKE_DATA 반환 **
    if (stats && stats->is_malicious) {
        struct stat st;
        if (fstat(fi->fh, &st) == -1) return -errno;
        off_t real_size = st.st_size;
        if (offset >= real_size) {
            log_line("READ", path, "ALLOW_FAKE", "policy:pid_flagged_eof", "size=0 offset=%ld pid=%d", (long)offset, (int)pid);
            return 0;
        }

        size_t to_read = size;
        if ((off_t)to_read > real_size - offset) {
            to_read = (size_t)(real_size - offset);
        }

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

        log_line("READ", path, "ALLOW_FAKE", "policy:pid_flagged", "size=%zu offset=%ld pid=%d", to_read, (long)offset, (int)pid);
        return (int)to_read;
    }

    // ** 3. 정상 PID인 경우, 실제 파일 읽기 (Real Read) **
    ssize_t res = pread(fi->fh, buf, size, offset);
    if (res == -1) {
        log_line("READ", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    // (정상 READ는 너무 많아서 로그 생략)
    return (int)res;
}

// unlink (*** 악성 PID 탐지 로직 포함 ***)
static int myfs_unlink(const char *path) {
    // ** 1. 현재 PID의 악성 상태 조회 **
    PidStats *stats = get_current_pid_stats();
    pid_t pid = (stats != NULL) ? stats->pid : (pid_t)-1;

    // ** 2. 이미 악성 PID로 플래그된 경우, 즉시 차단 **
    if (stats && stats->is_malicious) {
        log_line("UNLINK", path, "BLOCK", "policy:pid_flagged", "pid=%d", (int)pid);
        return -EPERM; // 권한 없음
    }

    // ** 3. 악성 여부 판단 (Rate Limit 체크) **
    int count = 0;
    if (stats) {
        stats->unlink_count++;
        count = stats->unlink_count;
    }
    
    // ** 4. 한도 초과 시, 악성으로 플래그하고 차단 **
    if (count > MAX_UNLINK_PER_WINDOW) {
        if (stats) stats->is_malicious = 1; // 악성 PID로 지정
        
        log_line("UNLINK", path, "BLOCK", "rate-limit",
                 "window=%ds max=%d count=%d pid=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count, (int)pid);
        return -EPERM; // 권한 없음
    }
    
    // ** 5. 정상 PID + 한도 이내인 경우, 실제 삭제 수행 **
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    if (unlinkat(base_fd, rel, 0) == -1) {
        log_line("UNLINK", path, "DENY", "os-error", "errno=%d", errno);
        return -errno; // OS 오류
    }
    
    log_line("UNLINK", path, "ALLOW", "policy:basic", 
             "window=%ds max=%d count=%d pid=%d",
             UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count, (int)pid);
    return 0;
}

// create
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    int fd = openat(base_fd, rel, fi->flags | O_CREAT, mode);
    if (fd == -1) {
        log_line("CREATE", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    fi->fh = fd;
    log_line("CREATE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// write (*** 원본 로직 유지: 항상 허용 ***)
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    ssize_t res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        log_line("WRITE", path, "DENY", "os-error", "errno=%d", errno);
        res = -errno;
    }
    log_line("WRITE", path, "ALLOW", "policy:basic", "size=%zu offset=%ld", size, (long)offset);
    return (int)res;
}

// release
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    log_line("RELEASE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// readdir (*** ls 지원 ***)
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
{
    (void)offset;
    (void)fi;
    (void)flags;

    char rel[PATH_MAX];
    get_relative_path(path, rel);

    int dir_fd = openat(base_fd, rel, O_RDONLY | O_DIRECTORY);
    if (dir_fd == -1) {
        log_line("READDIR", path, "DENY", "os-error-openat", "errno=%d", errno);
        return -errno;
    }

    DIR *dp = fdopendir(dir_fd);
    if (dp == NULL) {
        log_line("READDIR", path, "DENY", "os-error-fdopendir", "errno=%d", errno);
        close(dir_fd);
        return -errno;
    }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (filler(buf, de->d_name, NULL, 0, 0) != 0) {
            break;
        }
    }

    closedir(dp); // dp를 닫으면 dir_fd도 닫힘
    log_line("READDIR", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// utimens (*** touch 지원 ***)
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi)
{
    (void)fi;

    char rel[PATH_MAX];
    get_relative_path(path, rel);

    if (utimensat(base_fd, rel, tv, 0) == -1) {
        log_line("UTIMENS", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }

    log_line("UTIMENS", path, "ALLOW", "policy:basic", NULL);
    return 0;
}


// ========= main 함수 =========
int main(int argc, char *argv[]) {
    // 추적 테이블 초기화
    memset(g_pid_stats, 0, sizeof(g_pid_stats));
    
    // FUSE 인자 객체 초기화
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

    // 프로그램명(argv[0])을 FUSE 인자에 추가
    if (fuse_opt_add_arg(&args, argv[0]) == -1) {
        return -1;
    }

    // -f 옵션 추가 : 항상 포그라운드 모드로 실행
    if (fuse_opt_add_arg(&args, "-f") == -1) {
        return -1;
    }

    // 고정 마운트 지점: $HOME/workspace/target
    const char *home = getenv("HOME");
    char mountpoint[PATH_MAX];
    
    if (home != NULL) {
        // 환경변수 HOME이 존재하면 그 아래로 경로 결합
        snprintf(mountpoint, sizeof(mountpoint), "%s/workspace/target", home);
    }
    else {
        // HOME이 없을 때 폴백
        snprintf(mountpoint, sizeof(mountpoint), "/tmp/workspace/target");
    }

    // 마운트 지점 유효성 확인
    struct stat st;
    if (stat(mountpoint, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Mountpoint not found: %s\n", mountpoint);
        return -1;
    }

    // 베이스 디렉터리 fd 열기
    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open mountpoint");
        return -1;
    }

    //  로그 파일은 $HOME/myfs_log.txt
    char log_path[PATH_MAX];
    if (home != NULL) {
        snprintf(log_path, sizeof(log_path), "%s/myfs_log.txt", home);
    }
    else {
        snprintf(log_path, sizeof(log_path), "/tmp/myfs_log.txt");
    }
    log_fp = fopen(log_path, "a");
    if (!log_fp) {
        perror("fopen log");
    }

    log_line("START", "/", "ALLOW", "boot", "mountpoint=\"%s\"", mountpoint);

    // 마운트 경로를 FUSE 인자에 추가
    if (fuse_opt_add_arg(&args, mountpoint) == -1) {
        fprintf(stderr, "Failed to add mountpoint to fuse args\n");
        return -1;
    }

    // FUSE 실행 (myfs_oper 구조체 전달)
    static const struct fuse_operations myfs_oper = {
        .getattr = myfs_getattr,
        .open    = myfs_open,
        .read    = myfs_read,
        .unlink  = myfs_unlink,
        .create  = myfs_create,
        .write   = myfs_write,
        .release = myfs_release,
        .readdir = myfs_readdir, // ls 지원
        .utimens = myfs_utimens  // touch 지원
    };

    // FUSE 메인 루프 진입
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    // 종료 로그
    log_line("STOP", "/", "ALLOW", "shutdown", NULL);

    // 리소스 정리
    if (log_fp) {
        fclose(log_fp);
    }
    if (base_fd != -1) {
        close(base_fd);
    }
    fuse_opt_free_args(&args);
    return ret;
}
