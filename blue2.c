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
#include <ctype.h>

// 전역 상태
static int base_fd = -1; // 실제 로우 디렉터리 FD (마운트 대상 디렉터리)
static FILE *log_fp = NULL; // 로그 파일 스트림
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER; // 로그 동기화

// 대량 삭제 차단 파라미터
#define UNLINK_WINDOW_SEC      1   // 삭제 카운팅 윈도우(초)
#define MAX_UNLINK_PER_WINDOW  2    // 윈도우 내 허용 삭제 횟수(3번째부터 차단)
static time_t rl_window_start = 0;  // 현재 윈도우 시작 시각
static int rl_unlink_count = 0;     // 현재 윈도우 내 삭제 시도 누계

// 대량 읽기 차단 파라미터
#define READ_WINDOW_SEC 2 
#define MAX_READ_BYTES_PER_WINDOW (10*1024*1024) // 10MB/10s
						 
// PID별 읽기 상태 구조체
typedef struct {
	pid_t pid; // 추적 대상 PID
	time_t win_start; // 현재 윈도우 시작 시각
	size_t bytes; // 현 윈도우 동안 누적 읽기 바이트
	int blocked; // 임계치 초과로 차단 중인지(1: 차단, 0: 허용)
} ReadStats;

static ReadStats g_read_stats[1024];
static pthread_mutex_t g_read_lock = PTHREAD_MUTEX_INITIALIZER;

// 현재 FUSE 요청의 PID에 해당하는 ReadStats 포인터를 얻음
// 없으면 새 슬롯을 초기화하여 배정
// 너무 오래된 엔트리는 GC로 정리
// READ_WINDOW_SEC 초 경과 시 윈도우 리셋
static ReadStats* get_read_stats_for_current_pid(void) {
	struct fuse_context *fc = fuse_get_context();
	if(!fc) return NULL;
	pid_t p = fc->pid;

	pthread_mutex_lock(&g_read_lock);

	ReadStats *slot=NULL;
	ReadStats *empty=NULL; // 찾은 슬롯
	time_t now=time(NULL); // 비어있는 첫 슬롯

	for(int i=0; i < (int)(sizeof(g_read_stats)/sizeof(g_read_stats[0])); i++){
	    // 동일 PID 슬롯 찾기
	    if(g_read_stats[i].pid == p){
		slot = &g_read_stats[i];
		break;
	    }

	    // 비어있는 슬롯 기록(첫 번째만)
	    if(g_read_stats[i].pid==0 && !empty) {
		    empty = &g_read_stats[i];
	    }

	    // 동일 PID 슬롯 찾기
	    if(g_read_stats[i].pid!=0 && difftime(now, g_read_stats[i].win_start)>READ_WINDOW_SEC*5) {
		    memset(&g_read_stats[i], 0, sizeof(ReadStats));
	    }
	}
	if(!slot && empty) {
		// 새 슬롯 초기화
		empty->pid=p;
		empty->win_start=now;
		empty->bytes=0;
		empty->blocked=0;
	}

	// 윈도우 경과 시 리셋
	if(slot && difftime(now, slot->win_start)>=READ_WINDOW_SEC) {
		slot->win_start=now;
		slot->bytes=0;
	}
	pthread_mutex_unlock(&g_read_lock);
	return slot;
}

// 화이트리스트 확장자
// get_lower_ext()로 소문자화하여 비교 ->  목록은 전부 소문자로 유지
static const char *SENSITIVE_EXTS[] = {
  "doc","docx","docb","docm","dot","dotm","dotx",
  "xls","xlsx","xlsm","xlsb","xlw","xlt","xlm","xlc","xltx","xltm",
  "ppt","pptx","pptm","pot","pps","ppsm","ppsx","ppam","potx","potm",
  "pst","ost","msg","emi","edb","vsd","vsdx","txt","csv","rtf","123",
  "wks","wk1","pdf","dwg","onectoc2","snt","hwp","602","sxi","sti",
  "sldx","sldm","vdi","vmdk","vmx","gpg","aes","arc","paq","bz2",
  "tbk","bak","tar","tgz","gz","7z","rar","zip","backup","iso","vcd",
  "jpeg","jpg","bmp","png","gif","raw","cgm","tif","tiff","net","psd",
  "ai","svg","djvu","m4u","m3u","mid","wma","flv","3g2","mkv","3gp",
  "mp4","mov","avi","asf","mpeg","vob","mpg","wmv","fla","swf","wav",
  "mp3","sh","class","jar","java","rb","asp","php","jsp","brd","sch",
  "dch","dip","pl","vb","vbs","ps1","bat","cmd","js","asm","h","pas",
  "cpp","c","cs","suo","sln","ldf","mdf","ibd","myi","myd","frm",
  "odb","dbf","db","mdb","accdb","sql","sqlitedb","sqlite3","asc",
  "lay6","lay","mml","sxm","otg","odg","uop","std","sxd","otp","odp",
  "wb2","slk","dif","stc","sxc","ots","ods","3dm","max","3ds","uot",
  "stw","sxw","ott","odt","pem","p12","csr","crt","key","pfx","der", "tmp", "bin"
};

// 확장자 파싱/체크
// 파일명에서 마지막 . 뒤 확장자 추출 (소문자)
static void get_lower_ext(const char *name, char *ext_out, size_t ext_out_sz) {
    ext_out[0] = '\0'; // 기본 : 빈 문자열
    const char *p = strrchr(name, '.'); // 마지막 . 탐색
    if (!p) return; // 없으면 확장자 없음
    p++; // '.' 다음 문자부터 복사
    size_t i=0;
    while (*p && i+1<ext_out_sz) {
        ext_out[i++] = (char)tolower((unsigned char)*p++); // 소문자
    }
    ext_out[i] = '\0';
}
static int has_extension(const char *name) {
    const char *p = strrchr(name, '.');
    return (p && *(p+1) != '\0');
}

// 화이트리스트 포함 여부 검사
static int is_sensitive_ext(const char *ext) {
    if (!ext || !*ext) return 0; // 빈 확장자 -> 미포함
    for (size_t i=0;i<sizeof(SENSITIVE_EXTS)/sizeof(SENSITIVE_EXTS[0]);i++) {
	// 목록과 일치 -> 포함
        if (strcmp(ext, SENSITIVE_EXTS[i]) == 0) return 1;
    }
    return 0;
}

// 경로를 base_fd 기준 상대경로로 변환
// FUSE 콜백에 들어오는 path는 "/" 또는 "/foo/bar" 형태.
// 내부 openat/fstatat 등은 base_fd + relpath 로 수행
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) { // 루트 요청인 경우
        strcpy(relpath, "."); // 현재 디렉터리
    } else { // 일반 경로인 경우
        if (path[0] == '/') path++; // 선행 / 하나 제거 (상대경로로)
        strncpy(relpath, path, PATH_MAX);
        relpath[PATH_MAX - 1] = '\0'; // 널 종료 보장
    }
}

// 유틸: 파일 헤더(매직) 읽기 + 매직 판정
static ssize_t read_file_magic_at_base(const char *relpath, unsigned char *buf, size_t n) {
    int fd = openat(base_fd, relpath, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) return -1; // 열기 실패 -> 에러
    ssize_t r = pread(fd, buf, n, 0); // 파일 시작(0)에서 n바이트 읽기
    close(fd);
    return r; // 읽은 바이트 수
}
static int starts_with(const unsigned char *buf, ssize_t n, const void *sig, size_t siglen) {
    return (n >= (ssize_t)siglen && memcmp(buf, sig, siglen) == 0); // 최소 siglen만큼 읽혔고 동일하면 true
}

// 실행파일 매직 판별
static int is_exec_magic(const unsigned char *h, ssize_t n) {
    // 실행 포맷 대표: ELF, PE(MZ)
    if (starts_with(h,n,"\x7F""ELF",4)) return 1;
    if (n>=2 && h[0]=='M' && h[1]=='Z') return 1;
    return 0;
}
// 알고 있는 정상 매직만 엄격 매칭
static int magic_ok_for_ext(const char *ext, const unsigned char *h, ssize_t n) {
    if (!ext || !*ext || n<=0) return 1; // 정보 부족 → 허용(과차단 방지)

    // 이미지/문서 대표
    if (!strcmp(ext,"pdf"))   return starts_with(h,n,"%PDF",4);
    if (!strcmp(ext,"png"))   return starts_with(h,n,"\x89PNG",4);
    if (!strcmp(ext,"jpg") || !strcmp(ext,"jpeg")) return (n>=2 && h[0]==0xFF && h[1]==0xD8);
    if (!strcmp(ext,"gif"))   return starts_with(h,n,"GIF",3);
    if (!strcmp(ext,"tif") || !strcmp(ext,"tiff")) return (starts_with(h,n,"II*\0",4) || starts_with(h,n,"MM\0*",4));
    if (!strcmp(ext,"psd"))   return starts_with(h,n,"8BPS",4);

    // ZIP 계열 (docx/xlsx/pptx/…)
    if (!strcmp(ext,"zip")||!strcmp(ext,"docx")||!strcmp(ext,"xlsx")||!strcmp(ext,"pptx")||
        !strcmp(ext,"xltx")||!strcmp(ext,"xltm")||!strcmp(ext,"potx")||!strcmp(ext,"potm")||
        !strcmp(ext,"ppsx")||!strcmp(ext,"ppsm")||!strcmp(ext,"sldx")||!strcmp(ext,"sldm"))
        return starts_with(h,n,"PK\x03\x04",4);

    // 구형 OLE 계열(.doc/.xls/.ppt/.vsd/.msg, 일부 .hwp)
    if (!strcmp(ext,"doc")||!strcmp(ext,"xls")||!strcmp(ext,"ppt")||!strcmp(ext,"vsd")||!strcmp(ext,"msg")||!strcmp(ext,"hwp"))
        return starts_with(h,n,"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",8);

    // 압축
    if (!strcmp(ext,"gz")||!strcmp(ext,"tgz")) return (n>=2 && h[0]==0x1F && h[1]==0x8B);
    if (!strcmp(ext,"bz2")) return starts_with(h,n,"BZh",3);
    if (!strcmp(ext,"7z"))  return starts_with(h,n,"7z\xBC\xAF\x27\x1C",6);
    if (!strcmp(ext,"rar")) return (starts_with(h,n,"Rar!\x1A\x07\x00",7) || starts_with(h,n,"Rar!\x1A\x07\x01\x00",8));

    // DB/기타
    if (!strcmp(ext,"sqlite3")||!strcmp(ext,"sqlitedb"))
        return starts_with(h,n,"SQLite format 3",16);

    // 모르는 확장자 → 허용(과차단 방지)
    return 1;
}

 // 확장자 없음/화이트리스트 외 -> 무조건 '의심'(차단)
 // 화이트리스트 확장자면 헤더- 확장자 검사 수행
 // 우리가 아는 정상 매직과 불일치 -> 의심
 // 매직 모름 -> 허용
static int is_suspicious_for_open(const char *relpath) {
    char ext[32]; get_lower_ext(relpath, ext, sizeof(ext)); // 확장자 소문자 추출

    // 확장자 없음 -> 차단
    if (ext[0] == '\0') {
        return 1;
    }
    // 화이트리스트 외 확장자 -> 차단
    if (!is_sensitive_ext(ext)) {
        return 1;
    }

    // 존재하는 일반 파일 헤더 확인 (없거나 빈파일이면 과차단 방지로 통과)
    unsigned char h[16] = {0};
    ssize_t n = read_file_magic_at_base(relpath, h, sizeof(h));
    if (n <= 0) {
        return 0; // 정보 부족 -> 허용
    }

    // 아는 정상 매직과 불일치 -> 의심
    if (!magic_ok_for_ext(ext, h, n)) {
        return 1;
    }

    // 통과
    return 0;
}

// 로그 기록 (스레드 안전)
static void log_line(const char *action, const char *path, const char *result,
                     const char *reason, const char *extra_fmt, ...) {
    char ts[64]; // 타임스탬프
    time_t now = time(NULL); // 현재 epoch 초
    struct tm tm; // 지역 시간 구조체
    localtime_r(&now, &tm); // 스레드 안전 로컬타임
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

    uid_t uid; // UID
    pid_t pid; // PID
    struct fuse_context *fc = fuse_get_context(); // 현재 FUSE 호출 컨텍스트
    if (fc) {
	// 컨텍스트 있으면 값 채움
        uid = fc->uid;
        pid = fc->pid;
    } else { // 없으면 -1로 기록
        uid = (uid_t)-1;
        pid = (pid_t)-1;
    }

    char extra[256] = {0}; // 추가 정보 문자열
    if (extra_fmt && extra_fmt[0]) { // 포맷 문자열 있으면
        va_list ap;
        va_start(ap, extra_fmt); // 가변 인자 시작
        vsnprintf(extra, sizeof(extra), extra_fmt, ap); // 포맷 결과 작성
        va_end(ap); // 가변 인자 종료
    }

    pthread_mutex_lock(&log_lock); // 로그 쓰기 잠금
    if (log_fp) { // 로그 파일 열려 있으면
        fprintf(log_fp, "ts=%s uid=%d pid=%d action=%s path=\"%s\" result=%s",
                ts, (int)uid, (int)pid, action, path ? path : "", result ? result : "");
        if (reason) fprintf(log_fp, " reason=\"%s\"", reason); else fprintf(log_fp, " reason=\"\"");
        if (extra[0]) fprintf(log_fp, " extra=\"%s\"", extra);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
    pthread_mutex_unlock(&log_lock);
}

// 대량 삭제(UNLINK) 레이트 리밋
// 1초 내 2회까지 허용
static int unlink_rate_limit_exceeded(int *out_count_in_window) {
    time_t now = time(NULL);
    // 최초 호출이거나 윈도우 경과 시
    if (rl_window_start == 0 || difftime(now, rl_window_start) >= UNLINK_WINDOW_SEC) {
        rl_window_start = now;     // 새 윈도우 시작
        rl_unlink_count = 0;       // 카운트 리셋
    }
    rl_unlink_count++; // 현재 윈도우 카운트 증가
    if (out_count_in_window) *out_count_in_window = rl_unlink_count; // 호출자에게 현재 카운트 전달
    return (rl_unlink_count > MAX_UNLINK_PER_WINDOW); // 3번째부터 초과(true)
}

// FUSE 콜백

// getattr : 파일 메타데이터 조회
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    if (fstatat(base_fd, rel, stbuf, AT_SYMLINK_NOFOLLOW) == -1) return -errno;
    return 0;
}

// open : 화이트리스트 + 매직 검사 기반으로 위장 파일 차단 (정상은 허용)
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);

    // 존재하는 정규 파일만 검사 (디렉토리는 제외)
    struct stat st;
    int exists = (fstatat(base_fd, rel, &st, AT_SYMLINK_NOFOLLOW) == 0);

    if (exists && S_ISREG(st.st_mode)) {
        if (is_suspicious_for_open(rel)) { // 의심 판정(확장자/매직/실행매직)
            log_line("OPEN", path, "DENY", "suspicious:unknown-ext-or-magic-mismatch-or-exec-disguise", NULL);
            return -EACCES; // 위장/비정상 -> 차단
        }
    }

    int fd = openat(base_fd, rel, fi->flags); // 실제 openat 수행
    if (fd == -1) {
        log_line("OPEN", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    fi->fh = fd;
    // log_line("OPEN", path, "ALLOW", "policy:basic", "flags=0x%x", fi->flags);
    return 0; // 성공
}

// read : pid별 레이트 리밋(대량 읽기 억제) 적용
static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;

    // 현재 PID의 읽기 상태 슬롯 확보
    ReadStats *rs = get_read_stats_for_current_pid();
    pid_t cur_pid = -1;

    if (rs) {
	cur_pid = rs->pid;
    }

    // 차단 중인 PID면 즉시 거부
    if(rs && rs->blocked){
        log_line("READ", path, "BLOCK", "rate-limit-read", "pid=%d", (int)rs->pid);
         return -EPERM;
    }

    // 실제 읽기 수행
    int fd = (int)fi->fh;
    ssize_t res = pread(fd, buf, size, offset);
    if (res == -1) {
        log_line("READ", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }

    // 누계 업데이트 + 임계치 초과 시 차단 플래그 세팅
    // res > 0인 실제 읽기 바이트만 누계
    if (rs && res > 0) {
	int just_blocked = 0;
	pthread_mutex_lock(&g_read_lock);
	// 다시 윈도우 경과 체크(동시성 레이스 최소화)
	time_t now = time(NULL);
	if (difftime(now, rs->win_start) >= READ_WINDOW_SEC) {
	    rs->win_start = now;
	    rs->bytes = 0;
	    rs->blocked = 0;
	}
	rs->bytes += (size_t)res;
	if (rs->bytes > MAX_READ_BYTES_PER_WINDOW) { 
	    rs->blocked = 1;
	    just_blocked = 1;
	}
	pthread_mutex_unlock(&g_read_lock);

	if (just_blocked) {
	    log_line("READ", path, "FLAG", "rate-limit-read-tripped", "pid=%d bytes=%zu limit=%zu window=%ds", (int)cur_pid, rs->bytes, (size_t)MAX_READ_BYTES_PER_WINDOW, READ_WINDOW_SEC);
	}
    }

    return (int)res; // 읽은 바이트 수 반환
}

// unlink : 1초 윈도우 내 2회까지 허용, 초과 시 BLOCK
static int myfs_unlink(const char *path) {
    int count_in_window = 0;
    int exceeded = unlink_rate_limit_exceeded(&count_in_window);

    char rel[PATH_MAX];
    get_relative_path(path, rel);

    if (exceeded) {
        log_line("UNLINK", path, "BLOCK", "rate-limit",
                 "window=%ds max=%d count=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count_in_window);
        return -EPERM; // 대량 삭제 차단
    } else {
        // 한도 이내에서는 실제 삭제 수행
        if (unlinkat(base_fd, rel, 0) == -1) {
            log_line("UNLINK", path, "DENY", "os-error", "errno=%d", errno);
            return -errno;
        }
        log_line("UNLINK", path, "ALLOW", "policy:normal",
                 "window=%ds max=%d count=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count_in_window);
        return 0;
    }
}

// create : 새 파일 생성 시에도 확장자 정책 적용 (무확장자/화이트리스트 외 차단)
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);

    char ext[32]; get_lower_ext(rel, ext, sizeof(ext));
    if (ext[0] == '\0' || !is_sensitive_ext(ext)) {
        log_line("CREATE", path, "DENY", "suspicious:unknown-ext", NULL);
        return -EACCES;
    }

    int fd = openat(base_fd, rel, fi->flags | O_CREAT, mode);
    if (fd == -1) {
        log_line("CREATE", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    fi->fh = fd;
    log_line("CREATE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// write : 정상 쓰기 허용(오류만 로깅)
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;
    int fd = (int)fi->fh;
    ssize_t res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        log_line("WRITE", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    log_line("WRITE", path, "ALLOW", "policy:basic", "size=%zu offset=%ld", size, (long)offset);
    return (int)res;
}

// release : FD 정리
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    if (fi->fh) close((int)fi->fh);
    fi->fh = 0;
    log_line("RELEASE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// readdir : 디렉터리 나열 (ls 지원)
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
{
    (void)offset; // 오프셋
    (void)fi;     
    (void)flags;  // FUSE3의 확장 플래그

    char rel[PATH_MAX];
    get_relative_path(path, rel);

    // base_fd 기준으로 디렉터리 FD 열기 (O_DIRECTORY로 안전하게)
    int dir_fd = openat(base_fd, rel, O_RDONLY | O_DIRECTORY);
    if (dir_fd == -1) {
        // 디렉터리 열기 실패 -> 에러 로깅 후 errno 반환
        log_line("READDIR", path, "DENY", "os-error-openat", "errno=%d", errno);
        return -errno;
    }

    // FD -> DIR* 변환
    DIR *dp = fdopendir(dir_fd);
    if (dp == NULL) {
        // 변환 실패 시 FD 닫고 에러 처리
        log_line("READDIR", path, "DENY", "os-error-fdopendir", "errno=%d", errno);
        close(dir_fd);
        return -errno;
    }

    // 디렉터리 엔트리 순회
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (filler(buf, de->d_name, NULL, 0, 0) != 0) {
            // 사용자 버퍼가 꽉 찬 경우 조기 종료
            break;
        }
    }

    // DIR*를 닫으면 내부 FD도 같이 닫힘
    closedir(dp);

    // 성공 로그
    log_line("READDIR", path, "ALLOW", "policy:basic", NULL);
    return 0;
}


// main
int main(int argc, char *argv[]) {
    // FUSE 인자 초기화
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    if (fuse_opt_add_arg(&args, argv[0]) == -1) return -1;
    if (fuse_opt_add_arg(&args, "-f") == -1) return -1; // 항상 포그라운드

    // 마운트 경로: $HOME/workspace/target (없으면 종료)
    const char *home = getenv("HOME");
    char mountpoint[PATH_MAX];
    if (home) snprintf(mountpoint, sizeof(mountpoint), "%s/workspace/target", home);
    else      snprintf(mountpoint, sizeof(mountpoint), "/tmp/workspace/target");

    struct stat st;
    if (stat(mountpoint, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Mountpoint not found: %s\n", mountpoint);
        return -1;
    }

    // base_fd 오픈 (O_DIRECTORY로 안전)
    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open mountpoint");
        return -1;
    }

    // 로그 파일 열기
    char log_path[PATH_MAX];
    if (home) snprintf(log_path, sizeof(log_path), "%s/myfs_log.txt", home);
    else      snprintf(log_path, sizeof(log_path), "/tmp/myfs_log.txt");

    log_fp = fopen(log_path, "a");
    if (!log_fp) perror("fopen log");

    log_line("START", "/", "ALLOW", "boot", "mountpoint=\"%s\"", mountpoint);

    // FUSE에 마운트 경로 전달
    if (fuse_opt_add_arg(&args, mountpoint) == -1) {
        fprintf(stderr, "Failed to add mountpoint to fuse args\n");
        if (log_fp) fclose(log_fp);
        close(base_fd);
        return -1;
    }

    static const struct fuse_operations myfs_oper = {
        .getattr = myfs_getattr,
        .open    = myfs_open,
        .read    = myfs_read,
        .unlink  = myfs_unlink,
        .create  = myfs_create,
        .write   = myfs_write,
        .release = myfs_release,
        .readdir = myfs_readdir
    };

    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    log_line("STOP", "/", "ALLOW", "shutdown", NULL);

    if (log_fp) fclose(log_fp);
    if (base_fd != -1) close(base_fd);
    fuse_opt_free_args(&args);
    return ret;
}
