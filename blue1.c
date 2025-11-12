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

// 대량 삭제 차단
#define UNLINK_WINDOW_SEC      10 // 삭제 시도 수 측정할 시간(초)
#define MAX_UNLINK_PER_WINDOW  2  // 해당 윈도우에서 허용할 최대 삭제 시도 수
static time_t rl_window_start = 0; // 현재 윈도우 시작 시각
static int rl_unlink_count = 0;    // 현재 윈도우 내 삭제 시도 누계

// 특정 시간 윈도우 내 삭제 시도 횟수를 체크하는 함수
static int unlink_rate_limit_exceeded(int *out_count_in_window) {
    time_t now = time(NULL);
    // 현재 시간(now)이 기존 윈도우 시작 시각으로부터 UNLINK_WINDOW_SEC만큼 지났다면 새 윈도우 열기
    if (rl_window_start == 0 || difftime(now, rl_window_start) >= UNLINK_WINDOW_SEC) {
        rl_window_start = now;      // 새 윈도우 시작 시각 갱신
        rl_unlink_count = 0;        // 카운트 초기화
    }
    rl_unlink_count++;              // 카운트 1 증가
    if (out_count_in_window) *out_count_in_window = rl_unlink_count;
    // 현재 카운트가 허용 최대값을 초과하면 true 반환
    return (rl_unlink_count > MAX_UNLINK_PER_WINDOW);
}

// 경로 처리
static void get_relative_path(const char *path, char *relpath) {
    // 루트(/) 경로의 경우 . 로 치환
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        // /로 시작하면 제거 후 상대경로로 복사
        if (path[0] == '/') path++;
        strncpy(relpath, path, PATH_MAX);
        relpath[PATH_MAX - 1] = '\0'; // NULL 보장
    }
}

// 로그 함수
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
    } else {
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
        fprintf(log_fp, "ts=%s uid=%d pid=%d action=%s path=\"%s\" result=%s",
                ts, (int)uid, (int)pid, action, path ? path : "", result ? result : "");

        // 이유(reason) 출력
        if (reason) {
            fprintf(log_fp, " reason=\"%s\"", reason);
        } else {
            fprintf(log_fp, " reason=\"\"");
        }

        // 추가 정보(extra) 출력
        if (extra[0] != '\0') {
            fprintf(log_fp, " extra=\"%s\"", extra);
        }

        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
    pthread_mutex_unlock(&log_lock);
}

// ========= FUSE 콜백 =========

// getattr : 파일 속성 조회
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    if (fstatat(base_fd, rel, stbuf, AT_SYMLINK_NOFOLLOW) == -1) return -errno;
    return 0;
}

// open : 파일 열기
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    int fd = openat(base_fd, rel, fi->flags);
    if (fd == -1) return -errno;
    fi->fh = fd;
    return 0;
}

// read : 읽기 시 FAKE_DATA 반환 (보호 정책)
static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;
    struct stat st;

    // 현재 열려 있는 파일 핸들 기준으로 실제 파일 메타 데이터 조회 -> 실패시 -errno
    if (fstat(fi->fh, &st) == -1) {
        return -errno;
    }

    // 실제 파일 크기 구하기
    off_t real_size = st.st_size;

    // offset이 파일 크기보다 크면 EOF 처리 -> 0 바이트 반환
    if (offset >= real_size) {
        log_line("READ", path, "ALLOW_FAKE", "policy:mask", "size=0 offset=%ld", (long)offset);
        return 0;
    }

    // 실제로 채워줄 길이 계산
    // 요청 size와 파일 끝까지 남은 길이(real_size - offset) 중 작은 값
    size_t to_read = size;
    if ((off_t)to_read > real_size - offset) {
        to_read = (size_t)(real_size - offset);
    }

    // 패턴을 반복하여 buf 채움
    // 호출자가 요청한 offset을 고려해 패턴 내 시작 위치를 offset % 패턴길이로 정렬
    const char *pattern = "FAKE_DATA_BLOCK_0123456789\n";
    size_t plen = strlen(pattern);

    // 이번 읽기는 파일 전체 기준 offset에서 시작하므로
    // 패턴 내 시작 위치는 offset을 패턴 길이로 나눈 나머지
    size_t pos = (size_t)(offset % plen);

    // buf를 to_read 만큼 패턴으로 채움
    // 매 반복마다 패턴의 남은 구간(plen - pos) 또는 남은 필요량(to_read - filled) 중 작은 만큼만 복사
    size_t filled = 0;
    while (filled < to_read) {
        size_t chunk = plen - pos; // 패턴에서 이번에 가져올 수 있는 최대 길이
        if (chunk > to_read - filled) { // 실제 필요한 만큼만
            chunk = to_read - filled;
        }

        memcpy(buf + filled, pattern + pos, chunk); // 패턴 일부를 결과 버퍼에 복사
        filled += chunk; // 누적 복사량 갱신
        pos = 0; // 다음 반복부터는 패턴 시작부터
    }

    // offset == 0일 때 로깅
    if (offset == 0)
        log_line("READ", path, "ALLOW_FAKE", "policy:mask", "size=%zu offset=%ld", to_read, (long)offset);
    return (int)to_read; // 읽은 바이트 수 반환
}

// unlink : 삭제 차단 정책
static int myfs_unlink(const char *path) {
    int count_in_window = 0; // 현재 창에서 몇 번째 시도인지 기록
    int exceeded = unlink_rate_limit_exceeded(&count_in_window); // 대량 삭제 여부 판단
    if (exceeded) {
        // 대량 삭제로 판단된 경우, 거부 + 로깅
        log_line("UNLINK", path, "BLOCK", "rate-limit",
                 "window=%ds max=%d count=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count_in_window);
        return -EPERM; // 권한 없음
    } else {
        // 아직 한도 이내인 일반적인 삭제 시도 : 정책상 금지
        log_line("UNLINK", path, "DENY", "policy:protect",
                 "window=%ds max=%d count=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count_in_window);
        return -EACCES; // 접근 거부
    }
}

// create : 파일 생성
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    int fd = openat(base_fd, rel, fi->flags | O_CREAT, mode);
    if (fd == -1) return -errno;
    fi->fh = fd;
    log_line("CREATE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// write : 항상 허용
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    ssize_t res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) res = -errno;
    log_line("WRITE", path, "ALLOW", "policy:basic", "size=%zu offset=%ld", size, (long)offset);
    return (int)res;
}

// release : 파일 닫기
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    log_line("RELEASE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// ========= main 함수 =========
int main(int argc, char *argv[]) {
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
    // stat으로 존재 여부/타입 확인 -> 디렉터리가 아니면 에러
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

    // 로그 파일은 $HOME/myfs_log.txt
    // a 모드 : 존재하면 이어쓰기, 없으면 생성
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
        .release = myfs_release
    };

    // FUSE 메인 루프 진입
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    // 종료 로그
    log_line("STOP", "/", "ALLOW", "shutdown", NULL);

    // 리소스 정리
    if (log_fp) fclose(log_fp);
    if (base_fd != -1) close(base_fd);
    fuse_opt_free_args(&args);
    return ret;
}
