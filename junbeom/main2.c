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
#include <glib.h>
#include <sys/time.h>

static int base_fd = -1;
static FILE *log_fp = NULL;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOG_PATH "/home/kimjunbeom/ransom_fs.log"
#define LOG_BACKUP_DIR "/home/kimjunbeom/ransom_logs_backup"
#define RENAME_LIMIT 5
#define RENAME_INTERVAL 1

#define UNLINK_WINDOW_SEC 1
#define MAX_UNLINK_PER_WINDOW 2
static time_t rl_window_start = 0;
static int rl_unlink_count = 0;

#define READ_WINDOW_SEC 2
#define MAX_READ_BYTES_PER_WINDOW (10*1024*1024)

typedef struct {
    pid_t pid;
    time_t win_start;
    size_t bytes;
    int blocked;
} ReadStats;

static ReadStats g_read_stats[1024];
static pthread_mutex_t g_read_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int count;
    time_t last_time;
} RenameInfo;

static GHashTable *rename_table = NULL;
static pthread_mutex_t rename_lock = PTHREAD_MUTEX_INITIALIZER;

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
    "py", "rs", "go", "lua", "ts"
};

static const char *ransom_note_names[] = {
    "readme", "decrypt", "how_to", NULL
};


static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/') path++;
        strncpy(relpath, path, PATH_MAX);
        relpath[PATH_MAX - 1] = '\0';
    }
}

static void log_line(const char *action, const char *path, const char *result,
                     const char *reason, const char *extra_fmt, ...) {
    char ts[64];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

    uid_t uid;
    pid_t pid;
    struct fuse_context *fc = fuse_get_context();
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

static void get_ext(const char *name, char *ext_out, size_t ext_out_sz) {
    ext_out[0] = '\0';
    const char *p = strrchr(name, '.');
    if (!p) return;
    p++;
    size_t len = strlen(p);
    if (len >= ext_out_sz) len = ext_out_sz - 1;
    strncpy(ext_out, p, len);
    ext_out[len] = '\0';
}

static int is_sensitive_ext(const char *ext) {
    if (!ext || !*ext) return 0;
    
    gchar *casefolded_ext = g_utf8_casefold(ext, -1);
    if (!casefolded_ext) return 0;

    int found = 0;
    for (size_t i=0;i<sizeof(SENSITIVE_EXTS)/sizeof(SENSITIVE_EXTS[0]);i++) {
        if (g_strcmp0(casefolded_ext, SENSITIVE_EXTS[i]) == 0) {
            found = 1;
            break;
        }
    }

    g_free(casefolded_ext);
    return found;
}

static int is_whitelisted_and_has_ext(const char *path) {
    char ext[32];
    get_ext(path, ext, sizeof(ext));
    
    if (ext[0] == '\0') return 0;
    if (strcmp(ext, "exe") == 0) return 0;
    
    return is_sensitive_ext(ext);
}

static int is_ransom_note(const char *path) {
    gchar *casefolded_path = g_utf8_casefold(path, -1);
    if (!casefolded_path) return 0;

    int result = 0;
    for (const char **n = ransom_note_names; *n; n++) {
        gchar *casefolded_note = g_utf8_casefold(*n, -1);
        if (casefolded_note) {
            if (strstr(casefolded_path, casefolded_note)) {
                result = 1;
            }
            g_free(casefolded_note);
        }
        if (result) break;
    }

    g_free(casefolded_path);
    return result;
}


static ssize_t read_file_magic_at_base(const char *relpath, unsigned char *buf, size_t n) {
    int fd = openat(base_fd, relpath, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) return -1;
    ssize_t r = pread(fd, buf, n, 0);
    close(fd);
    return r;
}

static int starts_with(const unsigned char *buf, ssize_t n, const void *sig, size_t siglen) {
    return (n >= (ssize_t)siglen && memcmp(buf, sig, siglen) == 0);
}

static int magic_ok_for_ext(const char *ext, const unsigned char *h, ssize_t n) {
    if (!ext || !*ext || n<=0) return 1;

    if (!strcmp(ext,"pdf")) return starts_with(h,n,"%PDF",4);
    if (!strcmp(ext,"png")) return starts_with(h,n,"\x89PNG",4);
    if (!strcmp(ext,"jpg") || !strcmp(ext,"jpeg")) return (n>=2 && h[0]==0xFF && h[1]==0xD8);
    if (!strcmp(ext,"gif")) return starts_with(h,n,"GIF",3);
    if (!strcmp(ext,"tif") || !strcmp(ext,"tiff")) return (starts_with(h,n,"II*\0",4) || starts_with(h,n,"MM\0*",4));
    if (!strcmp(ext,"psd")) return starts_with(h,n,"8BPS",4);

    if (!strcmp(ext,"zip")||!strcmp(ext,"docx")||!strcmp(ext,"xlsx")||!strcmp(ext,"pptx")||
        !strcmp(ext,"xltx")||!strcmp(ext,"xltm")||!strcmp(ext,"potx")||!strcmp(ext,"potm")||
        !strcmp(ext,"ppsx")||!strcmp(ext,"ppsm")||!strcmp(ext,"sldx")||!strcmp(ext,"sldm"))
        return starts_with(h,n,"PK\x03\x04",4);

    if (!strcmp(ext,"doc")||!strcmp(ext,"xls")||!strcmp(ext,"ppt")||!strcmp(ext,"vsd")||!strcmp(ext,"msg")||!strcmp(ext,"hwp"))
        return starts_with(h,n,"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",8);

    if (!strcmp(ext,"gz")||!strcmp(ext,"tgz")) return (n>=2 && h[0]==0x1F && h[1]==0x8B);
    if (!strcmp(ext,"bz2")) return starts_with(h,n,"BZh",3);
    if (!strcmp(ext,"7z")) return starts_with(h,n,"7z\xBC\xAF\x27\x1C",6);
    if (!strcmp(ext,"rar")) return (starts_with(h,n,"Rar!\x1A\x07\x00",7) || starts_with(h,n,"Rar!\x1A\x07\x01\x00",8));

    if (!strcmp(ext,"sqlite3")||!strcmp(ext,"sqlitedb"))
        return starts_with(h,n,"SQLite format 3",16);

    return 1;
}

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

        if(g_read_stats[i].pid==0 && !empty) {
            empty = &g_read_stats[i];
        }

        if(g_read_stats[i].pid!=0 && difftime(now, g_read_stats[i].win_start)>READ_WINDOW_SEC*5) {
            memset(&g_read_stats[i], 0, sizeof(ReadStats));
        }
    }
    if(!slot && empty) {
        empty->pid=p;
        empty->win_start=now;
        empty->bytes=0;
        empty->blocked=0;
        slot = empty;
    }

    if(slot && difftime(now, slot->win_start)>=READ_WINDOW_SEC) {
        slot->win_start=now;
        slot->bytes=0;
        slot->blocked=0;
    }
    pthread_mutex_unlock(&g_read_lock);
    return slot;
}

static int is_suspicious_for_open(const char *relpath) {
    char ext[32]; get_ext(relpath, ext, sizeof(ext));

    if (ext[0] == '\0') {
        return 1;
    }
    if (!is_sensitive_ext(ext)) {
        return 1;
    }

    unsigned char h[16] = {0};
    ssize_t n = read_file_magic_at_base(relpath, h, sizeof(h));
    if (n <= 0) {
        return 0;
    }

    if (!magic_ok_for_ext(ext, h, n)) {
        return 1;
    }

    return 0;
}

static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char rel[PATH_MAX];
    get_relative_path(path, rel);
    if (fstatat(base_fd, rel, stbuf, AT_SYMLINK_NOFOLLOW) == -1) return -errno;
    return 0;
}

static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags)
{
    (void)offset; (void)fi; (void)flags;

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

static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char rel[PATH_MAX];
    get_relative_path(path, rel);

    struct stat st;
    int exists = (fstatat(base_fd, rel, &st, AT_SYMLINK_NOFOLLOW) == 0);

    if (exists && S_ISREG(st.st_mode)) {
        if (is_suspicious_for_open(rel)) {
            log_line("OPEN", path, "DENY", "suspicious:unknown-ext-or-magic-mismatch-or-exec-disguise", NULL);
            return -EACCES;
        }
    }

    int fd = openat(base_fd, rel, fi->flags);
    if (fd == -1) {
        log_line("OPEN", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    fi->fh = fd;
    return 0;
}

static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (!is_whitelisted_and_has_ext(relpath)) {
        log_line("CREATE", relpath, "BLOCKED", "File extension not in whitelist policy (e.g., .exe or no extension)", NULL);
        return -EPERM;
    }

    if (is_ransom_note(relpath)) {
        log_line("CREATE", relpath, "BLOCKED", "Ransom note name pattern detected", NULL);
        return -EPERM;
    }

    int fd = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (fd == -1) {
        log_line("CREATE", relpath, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    fi->fh = fd;
    log_line("CREATE", relpath, "ALLOW", "policy:basic", NULL);
    return 0;
}

static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;

    ReadStats *rs = get_read_stats_for_current_pid();
    pid_t cur_pid = -1;

    if (rs) {
        cur_pid = rs->pid;
    }

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

    if (rs && res > 0) {
        int just_blocked = 0;
        pthread_mutex_lock(&g_read_lock);
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

    return (int)res;
}

static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (offset == 0 && size >= 16) {
        char ext[32];
        get_ext(relpath, ext, sizeof(ext));
        
        if (!magic_ok_for_ext(ext, (const unsigned char *)buf, 16)) {
            log_line("WRITE", relpath, "BLOCKED", "Deep Magic number mismatch (16-byte signature check failed)", NULL);
            return -EPERM;
        }
    }

    int fd = (int)fi->fh;
    ssize_t res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        log_line("WRITE", path, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }
    log_line("WRITE", path, "ALLOW", "policy:basic", "size=%zu offset=%ld", size, (long)offset);
    return (int)res;
}

static int myfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    if (fi->fh) close((int)fi->fh);
    fi->fh = 0;
    log_line("RELEASE", path, "ALLOW", "policy:basic", NULL);
    return 0;
}

static int myfs_unlink(const char *path) {
    int count_in_window = 0;
    int exceeded = unlink_rate_limit_exceeded(&count_in_window);

    char rel[PATH_MAX];
    get_relative_path(path, rel);

    if (exceeded) {
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

static int myfs_mkdir(const char *path, mode_t mode) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = mkdirat(base_fd, relpath, mode);
    if (res == -1) return -errno;
    return 0;
}

static int myfs_rmdir(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1) return -errno;
    return 0;
}

static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    if (flags) return -EINVAL;

    pthread_mutex_lock(&rename_lock);

    RenameInfo *info = g_hash_table_lookup(rename_table, relfrom);
    if (!info) {
        info = calloc(1, sizeof(RenameInfo));
        g_hash_table_insert(rename_table, strdup(relfrom), info);
    }

    time_t now = time(NULL);
    if (info->last_time != 0 && now - info->last_time < RENAME_INTERVAL) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "Rename flood detected (per file)", NULL);
        return -EPERM;
    }
    if (info->count >= RENAME_LIMIT) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "Rename limit exceeded (per file)", NULL);
        return -EPERM;
    }

    if (!is_whitelisted_and_has_ext(relto)) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "New file extension not in whitelist policy", NULL);
        return -EPERM;
    }

    if (is_ransom_note(relto)) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "BLOCKED", "Ransom note name pattern detected", NULL);
        return -EPERM;
    }

    struct stat st;
    unsigned char h[16] = {0};
    ssize_t n_read = -1;
    char ext[32];
    get_ext(relto, ext, sizeof(ext));

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

    int res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1) {
        pthread_mutex_unlock(&rename_lock);
        log_line("RENAME", relto, "DENY", "os-error", "errno=%d", errno);
        return -errno;
    }

    info->count++;
    info->last_time = now;

    g_hash_table_remove(rename_table, relfrom);
    g_hash_table_insert(rename_table, strdup(relto), info);

    pthread_mutex_unlock(&rename_lock);

    log_line("RENAME", relto, "ALLOW", "Rename successful (per file count updated)", "old_path=%s", relfrom);
    return 0;
}

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

static const struct fuse_operations myfs_oper = {
    .getattr = myfs_getattr,
    .readdir = myfs_readdir,
    .open = myfs_open,
    .create = myfs_create,
    .read = myfs_read,
    .write = myfs_write,
    .release = myfs_release,
    .unlink = myfs_unlink,
    .mkdir = myfs_mkdir,
    .rmdir = myfs_rmdir,
    .rename = myfs_rename,
    .utimens = myfs_utimens,
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    rename_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, (GDestroyNotify)free);

    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (mountpoint == NULL) {
        perror("realpath");
        g_hash_table_destroy(rename_table);
        return -1;
    }

    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open base_fd");
        free(mountpoint);
        g_hash_table_destroy(rename_table);
        return -1;
    }

    char log_path[PATH_MAX];
    const char *home = getenv("HOME");
    if (home) snprintf(log_path, sizeof(log_path), "%s/ransom_fs.log", home);
    else snprintf(log_path, sizeof(log_path), "/tmp/ransom_fs.log");

    if (home) mkdir(LOG_BACKUP_DIR, 0700);

    log_fp = fopen(log_path, "a");
    if (!log_fp) {
        perror("fopen log");
    }

    log_line("START", "/", "ALLOW", "boot", "mountpoint=\"%s\"", mountpoint);

    free(mountpoint);

    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    log_line("STOP", "/", "ALLOW", "shutdown", NULL);

    if (log_fp) fclose(log_fp);
    if (base_fd != -1) close(base_fd);
    g_hash_table_destroy(rename_table);
    fuse_opt_free_args(&args);

    return ret;
}
