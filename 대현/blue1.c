#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h> 
#include <signal.h>
#include <math.h> // log2 함수 사용
#include <pthread.h> // 스레드 및 뮤텍스 사용
#include <ctype.h> 
#include <stdarg.h> 

// 전역 설정 및 상수 (랜섬웨어 방어 정책)

#define BACKUP_DIR_NAME ".snapshots"
#define LOG_FILE_PATH "/tmp/ransomware_defense.log"
#define BACKUP_COUNTER_FILE "backup_count.dat" // 백업 카운터를 저장할 파일명

// 파일별 쓰기 횟수 및 빈도 제한
#define MAX_WRITES_PER_FILE 5                   // 파일당 최대 쓰기 횟수 제한 (랜섬웨어 반복 쓰기 방어)
#define HIGH_ENTROPY_THRESHOLD 7.0              // 엔트로피 차단 임계값 (암호화 데이터 탐지)
#define WRITE_FREQUENCY_WINDOW 5                // 쓰기 빈도 감지 시간 창 (초)
#define MAX_WRITES_IN_WINDOW 10                 // 시간 창 내 최대 허용 쓰기 횟수
#define FILE_SIZE_CHANGE_THRESHOLD 0.8          // 파일 크기 변화 임계값 (80% 미만 감소 시 경고)
#define MIN_SIZE_FOR_SNAPSHOT 1024              // 스냅샷을 찍을 최소 파일 크기 (바이트)
#define MAX_TRACKED_FILES 1024                  // 추적할 파일 최대 개수

// 자료구조 및 전역 변수

static int base_fd = -1;        // 실제 마운트 대상 디렉터리 파일 디스크립터 FD

static FILE *log_fp = NULL;     // 로그 파일 포인터
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER; // 로그 제어

typedef struct {
    char path[PATH_MAX];                            // 파일 경로
    int write_count;                                // 파일에 대한 총 쓰기 횟수
    off_t initial_size;                             // 파일 최초 오픈 시 크기 (크기 변화 탐지용)
    time_t last_write_time;                         // 마지막 쓰기 시각
    time_t write_timestamps[MAX_WRITES_IN_WINDOW];  // 쓰기 발생 시각 목록
    int ts_count;                                   // 타임스탬프 배열에 저장된 횟수
} file_state_t;

// 파일 상태를 저장하는 배열 
static file_state_t file_states[MAX_TRACKED_FILES];
static int file_state_count = 0;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER; // 상태 배열 동기화


// file_state: 파일 경로를 기반으로 추적 상태를 검색하거나 새로 생성
static file_state_t* file_state(const char *path, off_t initial_size) {
    pthread_mutex_lock(&state_mutex);
    
    for (int i = 0; i < file_state_count; i++) {   // 기존 파일 상태 검색
	if (strcmp(file_states[i].path, path) == 0) {
	    pthread_mutex_unlock(&state_mutex);
	    return &file_states[i];
	}
    }

    if (file_state_count < MAX_TRACKED_FILES) {   // 새 파일 상태 생성
	file_state_t *new_state = &file_states[file_state_count++];
	strncpy(new_state->path, path, PATH_MAX);
	new_state->path[PATH_MAX - 1] = '\0';
	new_state->write_count = 0;
	new_state->initial_size = initial_size;
	new_state->last_write_time = 0;
	new_state->ts_count = 0;
	pthread_mutex_unlock(&state_mutex);
	return new_state;
    }

    pthread_mutex_unlock(&state_mutex);
    return NULL;      // 저장 공간 부족시 Null 반환
}

// log_action: 모든 파일시스템 동작 및 방어 행위를 로그 파일에 기록 
static void log_action(const char *action, const char *path, const char *result, const char *reason_fmt, ...) {
    uid_t uid;
    pid_t pid;

    struct fuse_context *context = fuse_get_context();  // fuse context 획득
    if (context) {
	uid = context->uid;         // 작업을 요청한 사용자의 user id
	pid = context->pid;         // 작업을 요청한 프로세스의 process id
    } else {
	uid = (uid_t)-1;
	pid = (pid_t)-1;
    }

    time_t timer;
    char time_buffer[32];       // 시간대 포함을 위해 32바이트 확보
    struct tm tm_info; 

    time(&timer); 
    localtime_r(&timer, &tm_info); // 스레드 안전한 지역 시간 변환
    strftime(time_buffer, 32, "%Y-%m-%dT%H:%M:%S%z", &tm_info);

    char reason_buffer[512] = {0}; 
    if (reason_fmt && *reason_fmt) {
	    va_list args; 
	    va_start(args, reason_fmt);
	    vsnprintf(reason_buffer, sizeof(reason_buffer), reason_fmt, args); 
	    // vsnprintf를 사용하여 가변 인자를 안전하게 로그 버퍼에 포맷팅
	    va_end(args);
    }

    pthread_mutex_lock(&log_lock); // 로그 파일 접근 잠금

    if (log_fp) { 
	fprintf(log_fp, 
	        "[%s] UID:%d PID:%d | ACTION:%s | PATH:%s | RESULT:%s | REASON:%s\n", 
	        time_buffer, uid, pid, action, path, result, 
	        (reason_buffer[0] != '\0') ? reason_buffer : "N/A");
	fflush(log_fp); // 버퍼 즉시 플러시 (실시간 로깅)
    } 
    else {
	fprintf(stderr, "LOG_FP_NULL [%s] ... (log_fp null error)\n", time_buffer);
    }

    pthread_mutex_unlock(&log_lock); // 로그 파일 접근 잠금 해제
}


// calculate_entropy: 주어진 버퍼의 샤논 엔트로피(Shannon Entropy)를 계산
static double calculate_entropy(const char *buf, size_t size) {
    if (size == 0) return 0.0;
	    
    int counts[256] = {0}; // 0~255 바이트 값의 빈도수
    for (size_t i = 0; i < size; i++) {
	counts[(unsigned char)buf[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
	if (counts[i] > 0) {
	    double probability = (double)counts[i] / size;
	    // 샤논 엔트로피 공식: -sum(p * log2(p))
	    entropy -= probability * log2(probability);
	}
    }
    return entropy;
}

// get_relative_path: FUSE 경로를 실제 디스크의 상대 경로로 변환
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
	strcpy(relpath, "."); // 루트 경로일 경우 '.' 반환
    } else {
	if (path[0] == '/')
	    path++; // 선행 '/' 제거
	strncpy(relpath, path, PATH_MAX); // PATH_MAX 크기만큼 복사
    }
}

// read_and_increment_backup_count: 백업 카운터를 읽고 1 증가시켜 저장 (파일에 저장)
static unsigned long read_and_increment_backup_count(const char *backup_dir_path) {
    char counter_path[PATH_MAX];
    snprintf(counter_path, PATH_MAX, "%s/%s", backup_dir_path, BACKUP_COUNTER_FILE);

    unsigned long count = 0;
	    
    // 1. 카운터 파일 읽기
    FILE *fp = fopen(counter_path, "r");
    if (fp) {
	if (fscanf(fp, "%lu", &count) != 1) { // 기존 카운트 값 읽기
	    count = 0; 
	}
	fclose(fp);
    }

    // 2. 카운터 증가
    count++;

    // 3. 카운터 파일 쓰기 (w 모드는 기존 내용을 덮어씀)
    fp = fopen(counter_path, "w");
    if (fp) {
	fprintf(fp, "%lu", count);
	fclose(fp);
    }

    return count; // 새 카운트 값 반환 (백업 파일명에 사용)
}


// create_snapshot: 파일의 현재 상태를 백업 디렉토리에 스냅샷으로 저장
static int create_snapshot(const char *path, const char *relpath) {
    char backup_full_path[PATH_MAX] = {0}; // 최종 백업 경로
    size_t remaining_len = PATH_MAX;       // 남은 버퍼 길이 추적 

    // 1. 백업 디렉토리 경로 구성
    char backup_dir_path[PATH_MAX];
    const char *home_dir = getenv("HOME");
    if (home_dir == NULL) home_dir = "/tmp"; 
	    
    size_t dir_len = snprintf(backup_dir_path, PATH_MAX, "%s/%s", home_dir, BACKUP_DIR_NAME);
    if (dir_len >= PATH_MAX) dir_len = PATH_MAX - 1; 
    backup_dir_path[dir_len] = '\0';
	    
    // 2. 백업 디렉토리 생성 (없으면)
    if (access(backup_dir_path, F_OK) == -1) {
	if (mkdir(backup_dir_path, 0700) == -1) {
	    log_action("SNAPSHOT", path, "FAIL", "Cannot create backup dir: %s", strerror(errno));
	    return -EIO;
	}
    }
	    
    // 3. 백업 카운터 읽기 및 증가
    unsigned long backup_id = read_and_increment_backup_count(backup_dir_path);

    // 4. 백업 파일명 생성 (카운터_경로)
    char count_str[20];
    snprintf(count_str, sizeof(count_str), "%lu", backup_id);
	    
    // relpath를 '_'로 변환 (경로 구분자를 제거하고 파일명으로 사용)
    char transformed_filename[PATH_MAX] = {0}; 
    size_t i = 0;
	    
    // 파일명 길이를 최종 경로 길이에 맞게 안전하게 제한
    const size_t fixed_overhead = strlen(backup_dir_path) + strlen(count_str) + 3; // 디렉토리 + 카운터 + 구분자 + 널 문자
    const size_t max_fname_len = (fixed_overhead < PATH_MAX) ? (PATH_MAX - fixed_overhead) : 0;
	    
    while (i < max_fname_len && relpath[i] != '\0') {
	transformed_filename[i] = (relpath[i] == '/') ? '_' : relpath[i];
	i++;
    }
    transformed_filename[i] = '\0'; 


    //  strcpy/strncat을 사용하여 경로 결합 
    
    // 1. 경로 시작 (백업 디렉토리 경로 복사)
    strncpy(backup_full_path, backup_dir_path, remaining_len);
    backup_full_path[PATH_MAX - 1] = '\0';
    remaining_len = PATH_MAX - strlen(backup_full_path);
	    
    // 2. 구분자 '/' 추가 (널 문자 공간 확보를 위해 2 지정)
    if (remaining_len > 1) {
	strncat(backup_full_path, "/", 2);
	remaining_len = PATH_MAX - strlen(backup_full_path);
    }
	    
    // 3. 카운터 추가 (예: 123)
    if (remaining_len > 1) {
	strncat(backup_full_path, count_str, remaining_len - 1);
	remaining_len = PATH_MAX - strlen(backup_full_path);
    }
	    
    // 4. 구분자 '_' 추가 (널 문자 공간 확보를 위해 2 지정)
    if (remaining_len > 1) {
	strncat(backup_full_path, "_", 2);
	remaining_len = PATH_MAX - strlen(backup_full_path);
    }

    // 5. 변환된 파일명 추가
    if (remaining_len > 1) {
	strncat(backup_full_path, transformed_filename, remaining_len - 1);
	remaining_len = PATH_MAX - strlen(backup_full_path);
    }

    // 최종 길이 검사
    if (remaining_len <= 1) {
	log_action("SNAPSHOT", path, "FAIL", "Path buffer overflow detected (Max length exceeded)");
	return -ENAMETOOLONG;
    }


    // 6. 파일 복사 (스냅샷 생성)
    int src_fd = openat(base_fd, relpath, O_RDONLY);
    if (src_fd == -1) {
	log_action("SNAPSHOT", path, "FAIL", "Cannot open source file via openat: %s", strerror(errno));
	return -errno;
    }
	    
    int dst_fd = open(backup_full_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dst_fd == -1) {
	close(src_fd);
	log_action("SNAPSHOT", path, "FAIL", "Cannot create backup file: %s", strerror(errno));
	return -errno;
    }
	    
    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
	if (write(dst_fd, buffer, bytes_read) != bytes_read) {
	    close(src_fd);
	    close(dst_fd);
	    log_action("SNAPSHOT", path, "FAIL", "Write error during copy: %s", strerror(errno));
	    return -EIO;
	}
    }

    close(src_fd);
    close(dst_fd);
    
    if (bytes_read == -1) {
	 log_action("SNAPSHOT", path, "FAIL", "Read error during copy: %s", strerror(errno));
	 return -EIO;
    }
    
    log_action("SNAPSHOT", path, "ALLOW", "Backup successful to %s", backup_full_path);
    return 0;
}

// is_whitelisted_extension: 주어진 파일의 확장자가 화이트리스트에 있는지 검사
static int is_whitelisted_extension(const char *path) {

    static const char *WHITELIST_EXTENSIONS[] = {
	// 문서/오피스 파일
	"doc", "docx", "docb", "docm", "dot", "dotm", "dotx", "xls", "xlsx", "xlsm", 
	"xlsb", "xlw", "xlt", "xlm", "xlc", "xltx", "xltm", "ppt", "pptx", "pptm", 
	"pot", "pps", "ppsm", "ppsx", "ppam", "potx", "potm", "pdf", "hwp", "rtf",
	"csv", "txt", "123", "wks", "wk1", "602", "sxi", "sti", "sldx", "sldm", 
	"mml", "sxm", "otg", "odg", "uop", "std", "sxd", "otp", "odp", "wb2", 
	"slk", "dif", "stc", "sxc", "ots", "ods", "uot", "stw", "sxw", "ott", "odt",
	
	// 이메일/데이터베이스/개발/가상화 파일
	"pst", "ost", "msg", "emi", "edb", "vsd", "vsdx", "onectoc2", "snt", "vdi", 
	"vmdk", "vmx", "sh", "class", "jar", "java", "rb", "asp", "php", "jsp", 
	"brd", "sch", "dch", "dip", "pl", "vb", "vbs", "ps1", "bat", "cmd", "js", 
	"asm", "h", "pas", "cpp", "c", "cs", "suo", "sln", "ldf", "mdf", "ibd", 
	"myi", "myd", "frm", "odb", "dbf", "db", "mdb", "accdb", "sql", "sqlitedb", 
	"sqlite3", "asc",
		
	// 백업/아카이브/보안 파일
	"gpg", "aes", "arc", "paq", "bz2", "tbk", "bak", "tar", "tgz", "gz", 
	"7z", "rar", "zip", "backup", "iso", "vcd", "pem", "p12", "csr", "crt", 
	"key", "pfx", "der", "tmp", "bin",

	// 이미지/CAD 파일
	"jpeg", "jpg", "bmp", "png", "gif", "raw", "cgm", "tif", "tiff", "net", 
	"psd", "ai", "svg", "djvu", "dwg", "3dm", "max", "3ds",
	
	// 미디어 파일
	"m4u", "m3u", "mid", "wma", "flv", "3g2", "mkv", "3gp", "mp4", "mov", 
	"avi", "asf", "mpeg", "vob", "mpg", "wmv", "fla", "swf", "wav", "mp3",

	NULL 
    };
	    
    const char *ext = strrchr(path, '.');

    if (!ext || ext == path) {
	    return 1; 
    }
    ext++; 
	    
    char lower_ext[PATH_MAX];
    size_t len = strlen(ext);
    if (len >= PATH_MAX) len = PATH_MAX - 1;

    for(size_t i = 0; i < len; i++) {
		lower_ext[i] = tolower((unsigned char)ext[i]);
    }
    lower_ext[len] = '\0';

    for (int i = 0; WHITELIST_EXTENSIONS[i] != NULL; i++) {
		if (strcmp(lower_ext, WHITELIST_EXTENSIONS[i]) == 0) {
		    return 1; 
		}
    }
    return 0; 
}

	// FUSE 연산 함수 (FUSE Operations)

// myfs_getattr: 파일 메타데이터(속성) 조회
static int myfs_getattr(const char *path, struct stat *stbuf,
		                struct fuse_file_info *fi) {
    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
		return -errno;

    return 0;
}

// myfs_open: 파일 열기 (쓰기 모드 시 파일 크기 초기값 저장)
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
    	return -errno;

    fi->fh = res;
	    
    // 쓰기 모드일 경우 초기 파일 크기 저장 (크기 변화 탐지용)
    if (fi->flags & (O_WRONLY | O_RDWR)) {
		struct stat st;
		if (fstat(res, &st) == 0) {
		    file_state(path, st.st_size);
		}
    }

    return 0;
}

// myfs_read: 파일 읽기
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
		             struct fuse_file_info *fi) {
    int res;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
		res = -errno;

    return res;
}

// myfs_write: 파일 쓰기 (핵심 랜섬웨어 방어 로직 적용)
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
		              struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    file_state_t *state = file_state(path, 0);

    // 1. 확장자 화이트리스트 검사 (랜섬웨어에 의한 확장자 변경 시도 차단)
    if (!is_whitelisted_extension(path)) {
    	log_action("WRITE", path, "DENY", "Extension not in whitelist (potential encrypted file)");
	    return -EPERM; // 권한 거부
    }
	    
    // 상태 추적 실패 시 기본 쓰기 허용 (과차단 방지)
    if (!state) {
		log_action("WRITE", path, "ALLOW", "State tracking failed (maybe full), allowing write");
		res = pwrite(fi->fh, buf, size, offset);
		return (res == -1) ? -errno : res;
    }

    // 2. 최대 쓰기 횟수 제한 (랜섬웨어의 반복적인 파일 덮어쓰기 차단)
    if (state->write_count >= MAX_WRITES_PER_FILE) {
		log_action("WRITE", path, "DENY", "Maximum write count exceeded (%d)", state->write_count);
		return -EPERM;
    }

    // 3. 고엔트로피 반복 시 차단 (랜섬웨어 암호화 데이터 탐지)
    double entropy = calculate_entropy(buf, size);
    if (entropy > HIGH_ENTROPY_THRESHOLD) {
		log_action("HIGH_ENTROPY_ALERT", path, "MONITOR", "High entropy detected (E=%.2f)", entropy);

		// 더 높은 임계값 초과 시 즉시 차단
		if (entropy > 7.5) { 
		     log_action("WRITE", path, "DENY", "Excessive high entropy write detected (E=%.2f)", entropy);
		     return -EPERM;
		}
    }

    // 4. 쓰기 빈도 감지 (단시간 내 대량 파일 쓰기 시도 방어)
    time_t now_s = time(NULL); 
	    
    pthread_mutex_lock(&state_mutex);
	    
    // 시간 창을 벗어난 오래된 타임스탬프 제거 및 카운트 리셋
    int i = 0;
    while (i < state->ts_count) {
		if (difftime(now_s, state->write_timestamps[i]) > WRITE_FREQUENCY_WINDOW) {
		    // 오래된 항목 제거 (배열의 마지막 요소를 현재 위치로 복사)
		    state->write_timestamps[i] = state->write_timestamps[state->ts_count - 1];
		    state->ts_count--;
		} else {
		    i++;
		}
    }

    // 현재 윈도우 내 쓰기 횟수 확인 (제한 초과 시 차단)
    if (state->ts_count >= MAX_WRITES_IN_WINDOW) {
		pthread_mutex_unlock(&state_mutex);
		log_action("WRITE", path, "DENY", "Write frequency limit exceeded (Count=%d)", state->ts_count);
		return -EPERM;
    }

    // 5. 백업 (스냅샷) - 파일에 첫 쓰기 요청 시 원본 파일 백업
    struct stat st;
    if (fstat(fi->fh, &st) == 0 && st.st_size > MIN_SIZE_FOR_SNAPSHOT && state->write_count == 0) {
		create_snapshot(path, relpath);
    }

    // 6. 실제 쓰기 수행
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
		pthread_mutex_unlock(&state_mutex);
		log_action("WRITE", path, "ERROR", "OS error: %s", strerror(errno));
		return -errno;
    }

    // 7. 쓰기 상태 업데이트 및 새 타임스탬프 기록
    state->write_count++;
    state->last_write_time = now_s;
    if (state->ts_count < MAX_WRITES_IN_WINDOW) {
		state->write_timestamps[state->ts_count++] = now_s;
    }

    // 8. 파일 크기 변화 탐지 (랜섬웨어의 파일 크기 줄임 시도 탐지)
    if (fstat(fi->fh, &st) == 0) {
		if (state->initial_size > 0 && 
		    (double)st.st_size < (double)state->initial_size * FILE_SIZE_CHANGE_THRESHOLD) {
		    log_action("FILE_SIZE_CHANGE", path, "ALERT", "Significant size reduction detected (from %ld to %ld)", (long)state->initial_size, (long)st.st_size);
		}
    }
	    
	    pthread_mutex_unlock(&state_mutex);
	    
	    log_action("WRITE", path, "ALLOW", "Write count %d", state->write_count);

	    return res;
}

static int myfs_release(const char *path, struct fuse_file_info *fi) {
    // 파일 핸들 닫기
    close(fi->fh);
	    return 0;
}

// myfs_readdir: 디렉터리 항목 나열
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		                off_t offset, struct fuse_file_info *fi,
		                enum fuse_readdir_flags flags) {
    DIR *dp;
    struct dirent *de;
    int fd;

    (void) offset;
    (void) fi;
    (void) flags;

    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1)
	return -errno;

    dp = fdopendir(fd);
    if (dp == NULL) {
		close(fd);
		return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0, 0))
		    break;
    }

	    closedir(dp);
	    return 0;
}

// myfs_create: 새 파일 생성 (정상 동작)
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    // 생성 시에도 확장자 검사 (화이트리스트에 없는 확장자 파일 생성 방지)
    if (!is_whitelisted_extension(path)) {
		log_action("CREATE", path, "DENY", "Extension not in whitelist");
		return -EPERM;
    }

    res = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (res == -1)
		return -errno;

	    fi->fh = res;
	    log_action("CREATE", path, "ALLOW", "Default file creation policy");
	    return 0;
}

// myfs_unlink: 파일 삭제 (정상 동작)
static int myfs_unlink(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
		return -errno;

    log_action("UNLINK", path, "ALLOW", "Default file deletion policy");
	    
    return 0;
}

// myfs_mkdir: 디렉터리 생성 (정상 동작)
static int myfs_mkdir(const char *path, mode_t mode) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
		return -errno;

	    log_action("MKDIR", path, "ALLOW", "Default directory creation policy");
	    
	    return 0;
}

// myfs_rmdir: 디렉터리 삭제 (정상 동작)
static int myfs_rmdir(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
		return -errno;

    log_action("RMDIR", path, "ALLOW", "Default directory deletion policy");

    return 0;
}

// myfs_rename: 파일/디렉터리 이름 변경 (정상 동작)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    if (flags)
		return -EINVAL;

    // 이름 변경 시 'to' 경로가 화이트리스트에 없는 확장자라면 차단
    if (!is_whitelisted_extension(to)) {
		log_action("RENAME", from, "DENY", "Target extension not in whitelist");
		return -EPERM;
    }

    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1)
		return -errno;

    log_action("RENAME", from, "ALLOW", "Default rename policy");

    return 0;
}

// myfs_utimens: 파일 접근 및 수정 시간 변경
static int myfs_utimens(const char *path, const struct timespec tv[2],
		                struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (fi != NULL && fi->fh != 0) {
	// 파일 핸들이 있는 경우
		res = futimens(fi->fh, tv);
    } else {
	// 파일 핸들이 없는 경우
		res = utimensat(base_fd, relpath, tv, 0);
    }
    if (res == -1)
		return -errno;

    return 0;
}


	// 파일시스템 연산자 구조체
static const struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .create     = myfs_create,
    .read       = myfs_read,
    .write      = myfs_write, // 핵심 방어 로직
    .release    = myfs_release,
    .unlink     = myfs_unlink,
    .mkdir      = myfs_mkdir,
    .rmdir      = myfs_rmdir,
    .rename     = myfs_rename,
    .utimens    = myfs_utimens,
};

// main: FUSE 파일시스템 실행 진입점
int main(int argc, char *argv[]) {
    // 1. FUSE 인자 초기화 및 프로그램 이름/포그라운드 옵션 추가
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    if (fuse_opt_add_arg(&args, argv[0]) == -1) return -1;
    if (fuse_opt_add_arg(&args, "-f") == -1) return -1; 
	    
    // 2. 고정된 마운트 경로 생성: /home/계정명/workspace/target
    const char *home = getenv("HOME");
    char fixed_mountpoint[PATH_MAX];
    if (home) {
		snprintf(fixed_mountpoint, sizeof(fixed_mountpoint), "%s/workspace/target", home);
    } else {
		// HOME 환경 변수 없는 경우, 에러 메시지 출력 후 종료
		fprintf(stderr, "Error: HOME environment variable not set. Cannot determine fixed mount point.\n");
		return -1;
    }
	    
    // 3. 로그 파일 열기 (전역 포인터 사용, "a" 모드)
    log_fp = fopen(LOG_FILE_PATH, "a"); // "a" (append) 모드
    if (log_fp == NULL) {
		perror("ERROR: Failed to open log file");
    } else {
		log_action("START", "/", "INIT", "--- Ransomware Defense FUSE Log Start ---");
    }

    // 4. 고정된 경로의 유효성 검사 및 base_fd 설정
    struct stat st;
    if (stat(fixed_mountpoint, &st) != 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "Error: Fixed mount target not found or is not a directory: %s\n", fixed_mountpoint);
		fprintf(stderr, "Please create this directory first: mkdir -p %s\n", fixed_mountpoint);
	    if(log_fp) fclose(log_fp);
		return -1;
    }

    // 마운트하기 전에 마운트 포인트 디렉터리를 열어 base_fd 설정
    base_fd = open(fixed_mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
		perror("open fixed mountpoint");
    	if(log_fp) fclose(log_fp);
		return -1;
    }

    // 5. FUSE 인자에 고정된 경로를 마운트 포인트로 추가
    if (fuse_opt_add_arg(&args, fixed_mountpoint) == -1) {
		fprintf(stderr, "Failed to add fixed mountpoint to fuse args\n");
		close(base_fd);
	    if(log_fp) fclose(log_fp);
		return -1;
    }
	    
    // 6. FUSE 파일시스템 실행
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    // 7. 종료 및 정리
    log_action("STOP", "/", "SHUTDOWN", "--- FUSE Log Shutdown ---");

    if (log_fp) { 
		fclose(log_fp);
    }

    close(base_fd);
    return ret;
}