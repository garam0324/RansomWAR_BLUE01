#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/time.h>
#include <math.h>

// 전역 상태
static int base_fd = -1;                          // 실제 로우 디렉터리 FD (마운트 대상 디렉터리)
static FILE *log_fp = NULL;                       // 로그 파일 포인
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER; // 로그 동기화

// UNLINK 레이트 리밋
// 일정 시간 창 안에서 허용할 최대 삭제 횟수
#define UNLINK_WINDOW_SEC      10   // 삭제 카운팅 윈도우(초)
#define MAX_UNLINK_PER_WINDOW  2    // 윈도우 내 허용 삭제 횟수
static time_t rl_window_start = 0;  // 현재 윈도우 시작 시각
static int rl_unlink_count = 0;     // 현재 윈도우 내 삭제 시도 누계

// READ 레이트 리밋
// PID별로 10초 동안 읽을 수 있는 최대 바이트 수 제한
#define READ_WINDOW_SEC 10
#define MAX_READ_BYTES_PER_WINDOW (10*1024*1024) // 10MB/10s

// RENAME 레이트 리밋
// 한 파일에 대해 너무 많은 rename 발생 방지
#define RENAME_INTERVAL 10
#define RENAME_LIMIT 3

// 스냅샷 / 엔트로피 / 쓰기 빈도 관련
#define BACKUP_DIR_NAME ".snapshots"
#define BACKUP_COUNTER_FILE "backup_count.dat" // 백업 카운터 파일명

#define MAX_WRITES_PER_FILE        5      // 파일당 최대 쓰기 횟수
#define HIGH_ENTROPY_THRESHOLD     7.0    // 엔트로피 경고 임계값
#define HIGH_ENTROPY_HARD_BLOCK    7.5    // 이 이상이면 바로 차단
#define FILE_BLOCK_COOLDOWN_SEC 10        // hard_block이면 10 동안 쓰기 금지
#define WRITE_FREQUENCY_WINDOW     5      // 쓰기 빈도 감지 창 (초)
#define MAX_WRITES_IN_WINDOW       10     // 창 내 최대 쓰기 횟수
#define FILE_SIZE_CHANGE_THRESHOLD 0.8    // 초기 크기의 80% 미만으로 줄어들면 경고
#define MIN_SIZE_FOR_SNAPSHOT      1024   // 스냅샷 찍을 최소 파일 크기
#define MAX_TRACKED_FILES          1024   // 추적할 파일수

// READ 레이트 리밋용 구조체(PID별)
typedef struct {
    pid_t pid;         // 추적 대상 PID
    time_t win_start;  // 현재 윈도우 시작 시각
    size_t bytes;      // 현 윈도우 동안 누적 읽기 바이트
    int blocked;       // 임계치 초과로 차단 중인지(1: 차단, 0: 허용)
} ReadStats;

static ReadStats g_read_stats[1024];
static pthread_mutex_t g_read_lock = PTHREAD_MUTEX_INITIALIZER;

// Rename 레이트 리밋용 구조체(파일별)
typedef struct {
    int count;         // 이 파일에 대해 지금까지 rename이 시도된 횟수
    time_t last_time;  // 마지막 rename 시도 시각
} RenameInfo;

#define MAX_RENAME_TRACK 1024 // 추적할 수 있는 파일 수 (rename 관련)

typedef struct {
    char path[PATH_MAX];      // 추적 중인 파일의 현재 경로
    RenameInfo info;          // 해당 파일의 rename 통계
    int in_use;               // 이 엔트리가 사용 중인지 (1: 사용, 0: 비어 있음)
} RenameEntry;

static RenameEntry rename_table[MAX_RENAME_TRACK];
static pthread_mutex_t rename_lock = PTHREAD_MUTEX_INITIALIZER;

// 파일별 쓰기 상태 (엔트로피/스냅샷/빈도)
typedef struct {
    char path[PATH_MAX];                            // FUSE 경로 (예: /foo/bar)
    int write_count;                                // 총 쓰기 횟수
    off_t initial_size;                             // 최초 오픈 시 파일 크기
    time_t last_write_time;                         // 마지막 쓰기 시각
    time_t write_timestamps[MAX_WRITES_IN_WINDOW];  // 쓰기 시각들
    int ts_count;                                   // 배열에 들어있는 개수
    int blocked;                                    // 1이면 임시 차단 상태
    time_t blocked_until;                           // 이 시각 전까진 모든 write 막음
} file_state_t;

static file_state_t file_states[MAX_TRACKED_FILES]; // 여러 파일의 상태 저장하는 배열
static int file_state_count = 0;                    // 현재 사용 중인 file_state 개수
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER; // file_state 보호용 뮤텍

// 확장자/패턴 화이트리스트 & 랜섬노트

// 보호해야 할 민감/중요 데이터 확장자 목록 (전부 소문자)
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
  "stw","sxw","ott","odt","pem","p12","csr","crt","key","pfx","der", "tmp", "bin",
  "py","rs","go","lua","ts"
};

// 랜섬노트 이름에 자주 등장하는 키워드 패턴
static const char *ransom_note_names[] = {
    "readme", "decrypt", "how_to", NULL
};

// 유틸 함수들
// 문자열 전체를 소문자로 변환
static void to_lower_str(const char *src, char *dst, size_t dst_sz) {
    size_t i;
    if (dst_sz == 0) return;
    for (i = 0; i < dst_sz - 1 && src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (char)tolower(c);
    }
    dst[i] = '\0';
}

// 파일명에서 마지막 . 뒤 확장자 추출하여 소문자로 변환
static void get_lower_ext(const char *name, char *ext_out, size_t ext_out_sz) {
    ext_out[0] = '\0';
    const char *p = strrchr(name, '.'); // 마지막 '.' 위치 찾기
    if (!p) return;                     // 확장자가 없으면 빈 문자열 유지
    p++;                                // '.' 다음 문자부터 확장자 시작
    size_t i=0;
    while (*p && i+1<ext_out_sz) {
        ext_out[i++] = (char)tolower((unsigned char)*p++);
    }
    ext_out[i] = '\0';
}

// 경로를 base_fd 기준 상대경로로 변환
// "/" 또는 "" -> "."으로 치환
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/') path++; // 맨 앞 '/' 제거
        strncpy(relpath, path, PATH_MAX);
        relpath[PATH_MAX - 1] = '\0';
    }
}

// 로그 기록 (스레드 안전)
static void log_line(const char *action, const char *path, const char *result,
                     const char *reason, const char *extra_fmt, ...) {
    char ts[64];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);                                  // 현재 시간 -> tm 구조체
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);    // ISO 유사 포맷 문자열로 변환

    uid_t uid;
    pid_t pid;
    struct fuse_context *fc = fuse_get_context();            // 현재 FUSE 요청 컨텍스 (UID, PID 등)
    if (fc) {
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

    pthread_mutex_lock(&log_lock);
    if (log_fp) {
        fprintf(log_fp, "ts=%s uid=%d pid=%d action=%s path=\"%s\" result=%s",
                ts, (int)uid, (int)pid, action, path ? path : "", result ? result : "");
        if (reason) fprintf(log_fp, " reason=\"%s\"", reason); else fprintf(log_fp, " reason=\"\"");
        if (extra[0]) fprintf(log_fp, " extra=\"%s\"", extra);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
    pthread_mutex_unlock(&log_lock);
}

// 파일 헤더(매직 넘버) 읽기
// openat 후 앞 n 바이트 읽기
static ssize_t read_file_magic_at_base(const char *relpath, unsigned char *buf, size_t n) {
    int fd = openat(base_fd, relpath, O_RDONLY | O_NOFOLLOW); // 심볼릭 링크 따라가지 않도록 O_NOFFLOW
    if (fd == -1) return -1;
    ssize_t r = pread(fd, buf, n, 0);
    close(fd);
    return r;
}

static int starts_with(const unsigned char *buf, ssize_t n, const void *sig, size_t siglen) {
    return (n >= (ssize_t)siglen && memcmp(buf, sig, siglen) == 0);
}

// 화이트리스트 확장자인지 확인
static int is_sensitive_ext(const char *ext) {
    if (!ext || !*ext) return 0;
    for (size_t i=0;i<sizeof(SENSITIVE_EXTS)/sizeof(SENSITIVE_EXTS[0]);i++) {
        if (strcmp(ext, SENSITIVE_EXTS[i]) == 0) return 1;
    }
    return 0;
}

// path에 확장자 존재 + 화이트리스트 안에 있는지 확인
// exe는 차단
static int is_whitelisted_and_has_ext(const char *path) {
    char ext[32];
    get_lower_ext(path, ext, sizeof(ext));

    if (ext[0] == '\0') return 0;          // 확장자 없음
    if (strcmp(ext, "exe") == 0) return 0; // exe는 차단

    return is_sensitive_ext(ext);
}

// 랜섬노트 이름 패턴 체크
// 경로 전체에서 readme, decrypt 등 포함되면 1 반환
static int is_ransom_note(const char *path) {
    char lower_path[PATH_MAX];
    to_lower_str(path, lower_path, sizeof(lower_path));

    for (const char **n = ransom_note_names; *n; n++) {
        if (strstr(lower_path, *n) != NULL) {
            return 1;
        }
    }
    return 0;
}

// 확장자와 매직 넘버 일치하는지 확인
// 모르는 확장자는 그냥 허용 (1 반환)
static int magic_ok_for_ext(const char *ext, const unsigned char *h, ssize_t n) {
    if (!ext || !*ext || n<=0) return 1; // 정보 부족 -> 판단 불가 -> 허용

    // 주요 포맷들에 대한 매직 넘버 체크
    if (!strcmp(ext,"pdf"))   return starts_with(h,n,(const unsigned char*)"%PDF",4);
    if (!strcmp(ext,"png"))   return starts_with(h,n,(const unsigned char*)"\x89PNG",4);
    if (!strcmp(ext,"jpg") || !strcmp(ext,"jpeg")) return (n>=2 && h[0]==0xFF && h[1]==0xD8);
    if (!strcmp(ext,"gif"))   return starts_with(h,n,(const unsigned char*)"GIF",3);
    if (!strcmp(ext,"tif") || !strcmp(ext,"tiff"))
        return (starts_with(h,n,(const unsigned char*)"II*\0",4) || starts_with(h,n,(const unsigned char*)"MM\0*",4));
    if (!strcmp(ext,"psd"))   return starts_with(h,n,(const unsigned char*)"8BPS",4);

	// ZIP / OOXML 계열
    if (!strcmp(ext,"zip")||!strcmp(ext,"docx")||!strcmp(ext,"xlsx")||!strcmp(ext,"pptx")||
        !strcmp(ext,"xltx")||!strcmp(ext,"xltm")||!strcmp(ext,"potx")||!strcmp(ext,"potm")||
        !strcmp(ext,"ppsx")||!strcmp(ext,"ppsm")||!strcmp(ext,"sldx")||!strcmp(ext,"sldm"))
        return starts_with(h,n,(const unsigned char*)"PK\x03\x04",4);

	// OLE 계열 (doc/xls/ppt/하나워드 등)
    if (!strcmp(ext,"doc")||!strcmp(ext,"xls")||!strcmp(ext,"ppt")||!strcmp(ext,"vsd")||
        !strcmp(ext,"msg")||!strcmp(ext,"hwp"))
        return starts_with(h,n,(const unsigned char*)"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",8);

	// 압축 포맷
    if (!strcmp(ext,"gz")||!strcmp(ext,"tgz")) return (n>=2 && h[0]==0x1F && h[1]==0x8B);
    if (!strcmp(ext,"bz2")) return starts_with(h,n,(const unsigned char*)"BZh",3);
    if (!strcmp(ext,"7z"))  return starts_with(h,n,(const unsigned char*)"7z\xBC\xAF\x27\x1C",6);
    if (!strcmp(ext,"rar"))
        return (starts_with(h,n,(const unsigned char*)"Rar!\x1A\x07\x00",7) ||
                starts_with(h,n,(const unsigned char*)"Rar!\x1A\x07\x01\x00",8));

	// sqlite 계열열
    if (!strcmp(ext,"sqlite3")||!strcmp(ext,"sqlitedb"))
        return starts_with(h,n,(const unsigned char*)"SQLite format 3",16);

    return 1; // 매직 넘버를 모르는 확장자는 검사하지 않음
}

// PID별 ReadStats 가져오기 및 생성성

static ReadStats* get_read_stats_for_current_pid(void) {
    struct fuse_context *fc = fuse_get_context();
    if(!fc) return NULL;
    pid_t p = fc->pid;

    pthread_mutex_lock(&g_read_lock);

    ReadStats *slot=NULL;
    ReadStats *empty=NULL;
    time_t now=time(NULL);

    for(int i=0; i < (int)(sizeof(g_read_stats)/sizeof(g_read_stats[0])); i++){
        if(g_read_stats[i].pid == p){
            slot = &g_read_stats[i];
            break;
        }
		// 오래된 엔트리 정리
        if(g_read_stats[i].pid==0 && !empty) {
            empty = &g_read_stats[i];
        }
        if(g_read_stats[i].pid!=0 && difftime(now, g_read_stats[i].win_start)>READ_WINDOW_SEC*5) {
            memset(&g_read_stats[i], 0, sizeof(ReadStats));
        }
    }
	
	// 아직 슬롯 없으면 새로 할당
    if(!slot && empty) {
        empty->pid=p;
        empty->win_start=now;
        empty->bytes=0;
        empty->blocked=0;
        slot = empty;
    }

	// 윈도우 초기화 시점
    if(slot && difftime(now, slot->win_start)>=READ_WINDOW_SEC) {
        slot->win_start=now;
        slot->bytes=0;
        slot->blocked=0;
    }
    pthread_mutex_unlock(&g_read_lock);
    return slot;
}

// UNLINK 레이트 리밋
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

// Rename 테이블에서 path에 해당하는 RenameInfo 찾기
// 없으면 새 엔트리 생성성
static RenameInfo *get_rename_info(const char *path) {
    int free_idx = -1;

    for (int i = 0; i < MAX_RENAME_TRACK; i++) {
        if (rename_table[i].in_use) {
            if (strcmp(rename_table[i].path, path) == 0) {
                return &rename_table[i].info;
            }
        } else if (free_idx == -1) {
            free_idx = i;
        }
    }

	// 새로 등록
    if (free_idx != -1) {
        rename_table[free_idx].in_use = 1;
        strncpy(rename_table[free_idx].path, path, PATH_MAX - 1);
        rename_table[free_idx].path[PATH_MAX - 1] = '\0';
        memset(&rename_table[free_idx].info, 0, sizeof(RenameInfo));
        return &rename_table[free_idx].info;
    }

	// 테이블 꽉 차면 NULL
    return NULL;
}

// Rename 이후 path 업데이트
static void update_rename_path_for_info(RenameInfo *info, const char *new_path) {
    for (int i = 0; i < MAX_RENAME_TRACK; i++) {
        if (rename_table[i].in_use && &rename_table[i].info == info) {
            strncpy(rename_table[i].path, new_path, PATH_MAX - 1);
            rename_table[i].path[PATH_MAX - 1] = '\0';
            return;
        }
    }
}

// 오래된 rename 엔트리 정리
static void cleanup_old_rename_entries(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_RENAME_TRACK; i++) {
        if (rename_table[i].in_use) {
            if (rename_table[i].info.last_time != 0 &&
                now - rename_table[i].info.last_time > RENAME_INTERVAL * 10) {
                rename_table[i].in_use = 0;
                memset(&rename_table[i].info, 0, sizeof(RenameInfo));
                rename_table[i].path[0] = '\0';
            }
        }
    }
}

// file_state 테이블에서 path에 해당하는 상태 찾기/생성
static file_state_t* file_state_get(const char *path, off_t initial_size) {
    pthread_mutex_lock(&state_mutex);

	// 이미 존재하는지 검색
    for (int i = 0; i < file_state_count; i++) {
        if (strcmp(file_states[i].path, path) == 0) {
            pthread_mutex_unlock(&state_mutex);
            return &file_states[i];
        }
    }

	// 새 엔트리 생성
    if (file_state_count < MAX_TRACKED_FILES) {
        file_state_t *st = &file_states[file_state_count++];
        strncpy(st->path, path, PATH_MAX - 1);
        st->path[PATH_MAX - 1] = '\0';
        st->write_count = 0;
        st->initial_size = initial_size;
        st->last_write_time = 0;
        st->ts_count = 0;
        st->blocked = 0;
		st->blocked_until = 0;

		// 더 이상 공간 없으면 추적 포기
        pthread_mutex_unlock(&state_mutex);
        return st;
    }

    pthread_mutex_unlock(&state_mutex);
    return NULL;
}

// 엔트로피 계산
// 데이터가 랜덤할수록 값이 커짐
static double calculate_entropy(const char *buf, size_t size) {
    if (size == 0) return 0.0;

    int counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[(unsigned char)buf[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// 백업 카운터 읽고 1 증가시켜 저장
// 백업 파일 이름을 고유하게 만들기 위함
static unsigned long read_and_increment_backup_count(const char *backup_dir_path) {
    char counter_path[PATH_MAX];
    snprintf(counter_path, PATH_MAX, "%s/%s", backup_dir_path, BACKUP_COUNTER_FILE);

    unsigned long count = 0;

    FILE *fp = fopen(counter_path, "r");
    if (fp) {
        if (fscanf(fp, "%lu", &count) != 1) {
            count = 0;
        }
        fclose(fp);
    }

    count++;

    fp = fopen(counter_path, "w");
    if (fp) {
        fprintf(fp, "%lu", count);
        fclose(fp);
    }

    return count;
}

// 스냅샷 생성
// $HOME/.snapshots/ 백업 디렉터리 아래에 "번호_원본경로" 형태로 복사본 만듦
static int create_snapshot(const char *path, const char *relpath) {
    char backup_dir_path[PATH_MAX];
    const char *home_dir = getenv("HOME");
    if (!home_dir) home_dir = "/tmp";

	// 백업 디렉터리 경로 : $HOME/.snapshots
    snprintf(backup_dir_path, PATH_MAX, "%s/%s", home_dir, BACKUP_DIR_NAME);
    backup_dir_path[PATH_MAX-1] = '\0';

    // 디렉터리 없으면 생성
    if (access(backup_dir_path, F_OK) == -1) {
        if (mkdir(backup_dir_path, 0700) == -1) {
            log_line("SNAPSHOT", path, "FAIL", "Cannot create backup dir", "errno=%d", errno);
            return -EIO;
        }
    }

	// 백업 번호 가져오기
    unsigned long backup_id = read_and_increment_backup_count(backup_dir_path);

    char count_str[32];
    snprintf(count_str, sizeof(count_str), "%lu", backup_id);

	// relpath 안의 '/'를 '_'로 바꿔 파일명으로 사용
    char transformed_filename[PATH_MAX] = {0};
    size_t i = 0;

    const size_t fixed_overhead = strlen(backup_dir_path) + strlen(count_str) + 3; // "/id_" 포함
    const size_t max_fname_len = (fixed_overhead < PATH_MAX) ? (PATH_MAX - fixed_overhead) : 0;

    while (i < max_fname_len && relpath[i] != '\0') {
        transformed_filename[i] = (relpath[i] == '/') ? '_' : relpath[i];
        i++;
    }
    transformed_filename[i] = '\0';

	// 최종 백업 경로 조합
    char backup_full_path[PATH_MAX] = {0};
    strncpy(backup_full_path, backup_dir_path, PATH_MAX-1);
    backup_full_path[PATH_MAX-1] = '\0';

    size_t remaining_len = PATH_MAX - strlen(backup_full_path);

    if (remaining_len > 1) {
        strncat(backup_full_path, "/", remaining_len-1);
        remaining_len = PATH_MAX - strlen(backup_full_path);
    }
    if (remaining_len > 1) {
        strncat(backup_full_path, count_str, remaining_len-1);
        remaining_len = PATH_MAX - strlen(backup_full_path);
    }
    if (remaining_len > 1) {
        strncat(backup_full_path, "_", remaining_len-1);
        remaining_len = PATH_MAX - strlen(backup_full_path);
    }
    if (remaining_len > 1) {
        strncat(backup_full_path, transformed_filename, remaining_len-1);
        remaining_len = PATH_MAX - strlen(backup_full_path);
    }

    if (remaining_len <= 1) {
        log_line("SNAPSHOT", path, "FAIL", "Path buffer overflow", NULL);
        return -ENAMETOOLONG;
    }

    int src_fd = openat(base_fd, relpath, O_RDONLY);
    if (src_fd == -1) {
        log_line("SNAPSHOT", path, "FAIL", "open source failed", "errno=%d", errno);
        return -errno;
    }

	// 백업 파일 open
    int dst_fd = open(backup_full_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dst_fd == -1) {
        close(src_fd);
        log_line("SNAPSHOT", path, "FAIL", "open dest failed", "errno=%d", errno);
        return -errno;
    }

	// 실제 복사
    char buf[4096];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, n) != n) {
            close(src_fd);
            close(dst_fd);
            log_line("SNAPSHOT", path, "FAIL", "write error", "errno=%d", errno);
            return -EIO;
        }
    }

    if (n == -1) {
        log_line("SNAPSHOT", path, "FAIL", "read error", "errno=%d", errno);
    }

    close(src_fd);
    close(dst_fd);

    log_line("SNAPSHOT", path, "ALLOW", "backup-ok", "dst=\"%s\"", backup_full_path);
    return 0;
}

// open 시 의심 파일 판단
// 화이트리스트 확장자인데 매직 넘버가 안 맞거나 화이트리스트 확장자가 아니면 차단
static int is_suspicious_for_open(const char *relpath) {
    char ext[32]; 
    get_lower_ext(relpath, ext, sizeof(ext));

	// 확장자 없으면 차단
    if (ext[0] == '\0') {
        return 1;
    }

	// 화이트리스트 아니면 차단
    if (!is_sensitive_ext(ext)) {
        return 1;
    }

	// 매직 넘버 검사
    unsigned char h[16] = {0};
    ssize_t n = read_file_magic_at_base(relpath, h, sizeof(h));
    if (n <= 0) {
        return 0; // 헤더 못 읽으면 판단 불가 -> 허용
    }

    if (!magic_ok_for_ext(ext, h, n)) {
        return 1;
    }

    return 0;
}

// FUSE 콜백 구현
// getattr
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    if (fstatat(base_fd, rel, stbuf, AT_SYMLINK_NOFOLLOW) == -1) return -errno;
    return 0;
}

// readdir
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
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0) != 0) {
            break;
        }
    }
    closedir(dp);
    log_line("READDIR", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// open : 확장자/매직 기반 위장 파일 차단 + 쓰기용 파일 상태 초기화
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);

    struct stat st;
    int exists = (fstatat(base_fd, rel, &st, AT_SYMLINK_NOFOLLOW) == 0);

	// 기존 파일에 대해 위장 검사
    if (exists && S_ISREG(st.st_mode)) {
        if (is_suspicious_for_open(rel)) {
            log_line("OPEN", path, "DENY", "suspicious:unknown-ext-or-magic-mismatch-or-exec-disguise", NULL);
            return -EACCES;
        }
    }

	// 실제 open
    int fd = openat(base_fd, rel, fi->flags);
    if (fd == -1) {
        log_line("OPEN", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    fi->fh = fd;

    // 쓰기 모드면 초기 사이즈 기록
    if (fi->flags & (O_WRONLY | O_RDWR)) {
        if (fstat(fd, &st) == 0) {
            file_state_get(path, st.st_size);
        }
    }

    return 0;
}

// create : 확장자 화이트리스트 + 랜섬노트 이름 차단
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);

	// 허용된 확장자가 아니면 차단
    if (!is_whitelisted_and_has_ext(rel)) {
        log_line("CREATE", rel, "BLOCKED", "File extension not in whitelist policy (e.g., .exe or no extension)", NULL);
        return -EPERM;
    }

	// 랜섬노트 차단
    if (is_ransom_note(rel)) {
        log_line("CREATE", rel, "BLOCKED", "Ransom note name pattern detected", NULL);
        return -EPERM;
    }

	// 실제 파일 생성
    int fd = openat(base_fd, rel, fi->flags | O_CREAT, mode);
    if (fd == -1) {
        log_line("CREATE", rel, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    fi->fh = fd;

    // 새 파일의 initial_size는 0으로 기록
    file_state_get(path, 0);

    log_line("CREATE", rel, "ALLOW", "policy:basic", NULL);
    return 0;
}

// read : PID별 레이트 리밋
static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;

    ReadStats *rs = get_read_stats_for_current_pid();
    pid_t cur_pid = -1;

    if (rs) {
        cur_pid = rs->pid;
    }

	// 이미 차단 상태면 바로 거부
    if(rs && rs->blocked){
        log_line("READ", path, "BLOCK", "rate-limit-read", "pid=%d", (int)rs->pid);
        return -EPERM;
    }

    int fd = (int)fi->fh;
    ssize_t res = pread(fd, buf, size, offset);
    if (res == -1) {
        log_line("READ", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }

	// 읽기량 누적 / 임계 초과 검사
    if (rs && res > 0) {
        int just_blocked = 0;
        pthread_mutex_lock(&g_read_lock);
        time_t now = time(NULL);

		// 윈도우 리셋셋
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
            log_line("READ", path, "FLAG", "rate-limit-read-tripped",
                     "pid=%d bytes=%zu limit=%zu window=%ds",
                     (int)cur_pid, rs->bytes, (size_t)MAX_READ_BYTES_PER_WINDOW, READ_WINDOW_SEC);
        }
    }

    return (int)res;
}

// write : 매직 검사 + 엔트로피/스냅샷/빈도/크기 감소 탐지 + 2번 연속 쓰기 방지
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int fd = (int)fi->fh;

	// 1) 파일 상태 조회 및 high_entropy BLOCK 쿨다운 확인
    file_state_t *state = file_state_get(path, 0);
    time_t now_s = time(NULL);

    // 이 파일이 이전 high-entropy로 인해 임시 차단 상태인지 확인
    if (state) {
        pthread_mutex_lock(&state_mutex);
        if (state->blocked) {
            if (now_s < state->blocked_until) {
                // 아직 쿨다운 중이면 모든 write 거부
                pthread_mutex_unlock(&state_mutex);
                log_line("WRITE", path, "BLOCKED",
                         "file-temporarily-blocked-after-high-entropy",
                         "blocked_until=%ld now=%ld",
                         (long)state->blocked_until, (long)now_s);
                return -EPERM;
            } else {
                // 쿨다운 시간 지났으면 차단 해제
                state->blocked = 0;
                state->blocked_until = 0;
            }
        }
        pthread_mutex_unlock(&state_mutex);
    }


    // 2) 매직 검사 (처음 쓰기 시 헤더 체크)
    if (offset == 0 && size >= 16) {
        char ext[32];
        get_lower_ext(relpath, ext, sizeof(ext));
        if (!magic_ok_for_ext(ext, (const unsigned char *)buf, 16)) {
            log_line("WRITE", relpath, "BLOCKED", "Deep Magic number mismatch (16-byte signature check failed)", NULL);
            return -EPERM;
        }
    }

	// 3) 엔트로피/빈도/스냅샷
    if (state) {
        // 최대 쓰기 횟수 제한
        if (state->write_count >= MAX_WRITES_PER_FILE) {
            log_line("WRITE", path, "BLOCKED", "max-write-count-exceeded", "count=%d", state->write_count);
            return -EPERM;
        }

        // 엔트로피 검사
        double entropy = calculate_entropy(buf, size);
        if (entropy > HIGH_ENTROPY_HARD_BLOCK) {
			if (state) {
				pthread_mutex_lock(&state_mutex);
				state->blocked = 1;
				state->blocked_until = now_s + FILE_BLOCK_COOLDOWN_SEC;
				pthread_mutex_unlock(&state_mutex);
			}
            log_line("WRITE", path, "BLOCKED", "excessive-high-entropy", "entropy=%.2f size=%zu offset=%ld cooldown=%ds", entropy, size, (size_t)offset, FILE_BLOCK_COOLDOWN_SEC);
            return -EPERM;
        } else if (entropy > HIGH_ENTROPY_THRESHOLD) {
			// 경고만 찍고 허용
            log_line("WRITE", path, "FLAG", "high-entropy", "entropy=%.2f", entropy);
	}

        // 쓰기 빈도 창 관리
        pthread_mutex_lock(&state_mutex);
        int i = 0;
        while (i < state->ts_count) {
            if (difftime(now_s, state->write_timestamps[i]) > WRITE_FREQUENCY_WINDOW) {
				// 윈도우 밖의 오래된 타임스탬프 제거
                state->write_timestamps[i] = state->write_timestamps[state->ts_count - 1];
                state->ts_count--;
            } else {
                i++;
            }
        }

        if (state->ts_count >= MAX_WRITES_IN_WINDOW) {
            pthread_mutex_unlock(&state_mutex);
            log_line("WRITE", path, "BLOCKED", "write-frequency-limit-exceeded", "count=%d", state->ts_count);
            return -EPERM;
        }
        pthread_mutex_unlock(&state_mutex);

        // 첫 쓰기 시 스냅샷 (원본 보존)
        struct stat st_before;
        if (fstat(fd, &st_before) == 0 &&
            st_before.st_size > MIN_SIZE_FOR_SNAPSHOT &&
            state->write_count == 0) {
            create_snapshot(path, relpath);
			
            // initial_size가 0이었다면 여기서 채워줌
            if (state->initial_size == 0)
                state->initial_size = st_before.st_size;
        }
    }

    // 4) 실제 write 수행
    ssize_t res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        log_line("WRITE", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }

    // 5) 상태 업데이트 + 크기 감소 감지지
    if (state) {
        pthread_mutex_lock(&state_mutex);

        state->write_count++;
        state->last_write_time = now_s;
        if (state->ts_count < MAX_WRITES_IN_WINDOW) {
            state->write_timestamps[state->ts_count++] = now_s;
        }

        struct stat st_after;
        if (fstat(fd, &st_after) == 0) {
			// 초기 크기 대비 너무 즐어들면 경고
            if (state->initial_size > 0 &&
                (double)st_after.st_size < (double)state->initial_size * FILE_SIZE_CHANGE_THRESHOLD) {
                log_line("WRITE", path, "FLAG", "file-size-drop",
                         "from=%ld to=%ld", (long)state->initial_size, (long)st_after.st_size);
            }
        }

        pthread_mutex_unlock(&state_mutex);

        log_line("WRITE", path, "ALLOW", "write-ok", "count=%d", state->write_count);
    } else {
		// state 테이블에서 추적하지 못한 경우
        log_line("WRITE", path, "ALLOW", "state-tracking-missed", "size=%zu offset=%ld", size, (long)offset);
    }

    return (int)res;
}

// release
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    if (fi->fh) close((int)fi->fh);
    fi->fh = 0;
    log_line("RELEASE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

// unlink : 삭제 레이트 리밋
static int myfs_unlink(const char *path) {
    int count_in_window = 0;
    int exceeded = unlink_rate_limit_exceeded(&count_in_window);

    char rel[PATH_MAX];
    get_relative_path(path, rel);

    if (exceeded) {
		// 윈도우 내 삭제 횟수 초과 -> 차단
        log_line("UNLINK", path, "BLOCK", "rate-limit",
                 "window=%ds max=%d count=%d",
                 UNLINK_WINDOW_SEC, MAX_UNLINK_PER_WINDOW, count_in_window);
        return -EPERM;
    } else {
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

// mkdir
static int myfs_mkdir(const char *path, mode_t mode) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = mkdirat(base_fd, relpath, mode);
    if (res == -1) return -errno;
    return 0;
}

// rmdir
static int myfs_rmdir(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1) return -errno;
    return 0;
}

// rename : 각 파일마다 rename 레이트리밋 + 확장자/매직/랜섬노트 검사
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    if (flags) return -EINVAL;

    pthread_mutex_lock(&rename_lock);

	// 오래된 엔트리 제거
    cleanup_old_rename_entries();

    RenameInfo *info = get_rename_info(relfrom);
    if (!info) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "Rename tracking table full", NULL);
        return -EPERM;
    }

    time_t now = time(NULL);
    if (info->last_time != 0 && now - info->last_time < 1 /* RENAME_INTERVAL */) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "Rename flood detected (per file)", NULL);
        return -EPERM;
    }

	// 허용 횟수 초과
    if (info->count >= 5) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "Rename limit exceeded (per file)", NULL);
        return -EPERM;
    }

	// 새 이름이 화이트리스트 확장자가 아니면 차단
    if (!is_whitelisted_and_has_ext(relto)) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "New file extension not in whitelist policy", NULL);
        return -EPERM;
    }

	// 새 이름이 랜섬노트면 차단
    if (is_ransom_note(relto)) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "Ransom note name pattern detected", NULL);
        return -EPERM;
    }

	// rename 전 매직 검사 (위장 확장자 방지)
    struct stat st;
    unsigned char h[16] = {0};
    ssize_t n_read = -1;
    char ext[32];
    get_lower_ext(relto, ext, sizeof(ext));

    if (fstatat(base_fd, relfrom, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode)) {
        n_read = read_file_magic_at_base(relfrom, h, sizeof(h));

        if (n_read > 0) {
            if (!magic_ok_for_ext(ext, h, n_read)) {
                pthread_mutex_unlock(&rename_lock);
                log_line("RENAME", relto, "BLOCKED", "Deep Magic number mismatch (16-byte signature failed for new extension)", NULL);
                return -EPERM;
            }
        }
    }

	// 실제 rename 수행
    int res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }

	// 통계 갱신
    info->count++;
    info->last_time = now;
    update_rename_path_for_info(info, relto);

    pthread_mutex_unlock(&rename_lock);

    log_line("RENAME", relto, "ALLOW", "Rename successful (per file count updated)", "old_path=%s", relfrom);
    return 0;
}

// utimens
static int myfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (fi != NULL && fi->fh != 0) {
        res = futimens(fi->fh, tv);
    } else {
        res = utimensat(base_fd, relpath, tv, 0);
    }
    if (res == -1) return -errno;
    return 0;
}

// main : FUSE 초기화 및 마운트
int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    if (fuse_opt_add_arg(&args, argv[0]) == -1) return -1; // argv[0] (프로그램 이름) 추가
    if (fuse_opt_add_arg(&args, "-f") == -1) return -1; // 항상 포그라운드 (-f)

    // 마운트 경로: $HOME/workspace/target
    const char *home = getenv("HOME");
    char mountpoint[PATH_MAX];
    if (home) snprintf(mountpoint, sizeof(mountpoint), "%s/workspace/target", home);
    else      snprintf(mountpoint, sizeof(mountpoint), "/tmp/workspace/target");

	// 마운트 디렉터리 존재 확인
    struct stat st;
    if (stat(mountpoint, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Mountpoint not found: %s\n", mountpoint);
        return -1;
    }

	// base_fd : 실제 디렉터리 FD
    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open mountpoint");
        return -1;
    }

    // 로그 파일: $HOME/myfs_log.txt
    char log_path[PATH_MAX];
    if (home) snprintf(log_path, sizeof(log_path), "%s/myfs_log.txt", home);
    else      snprintf(log_path, sizeof(log_path), "/tmp/myfs_log.txt");

    log_fp = fopen(log_path, "a");
    if (!log_fp) perror("fopen log");

    log_line("START", "/", "ALLOW", "boot", "mountpoint=\"%s\"", mountpoint);

    // FUSE 인자에 마운트포인트 추가
    if (fuse_opt_add_arg(&args, mountpoint) == -1) {
        fprintf(stderr, "Failed to add mountpoint to fuse args\n");
        if (log_fp) fclose(log_fp);
        close(base_fd);
        return -1;
    }

    // FUSE 콜백 테이블
    static const struct fuse_operations myfs_oper = {
        .getattr = myfs_getattr,
        .readdir = myfs_readdir,
        .open    = myfs_open,
        .create  = myfs_create,
        .read    = myfs_read,
        .write   = myfs_write,
        .release = myfs_release,
        .unlink  = myfs_unlink,
        .mkdir   = myfs_mkdir,
        .rmdir   = myfs_rmdir,
        .rename  = myfs_rename,
        .utimens = myfs_utimens,
    };
	
    // FUSE 메인 루프 진입
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    log_line("STOP", "/", "ALLOW", "shutdown", NULL);

    // 정리
    if (log_fp) fclose(log_fp);
    if (base_fd != -1) close(base_fd);
    fuse_opt_free_args(&args);
    return ret;
}
