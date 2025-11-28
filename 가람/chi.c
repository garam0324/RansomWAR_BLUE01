#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <sys/stat.h>
#include <stdint.h>

#define CHI_MIN_SAMPLE_SIZE 256      // 너무 작으면 의미 없음 → 평균에서 제외
#define MAX_SAMPLE_BYTES    (4*1024*1024) // 한 파일에서 최대 4MB만 샘플링

/**********************
 * 확장자 분류 관련
 **********************/
static const char *TEXT_EXTS[] = {
    "txt","log","rtf","md",
    "c","h","cpp","hpp","cc","hh","asm",
    "py","java","js","ts","tsc","rs","go",
    "rb","sh","pl","lua","vb","vbs",
    "asp","php","jsp","ps1","bat","cmd",
    "json","xml","html","htm","csv","ini",
    "cfg","yml","yaml",
    "doc","docx","dot","dotx",
    "ppt","pptx",
    "xls","xlsx",
    "suo","sln",
    "msg","pst","ost",
    NULL
};

// "원래부터 엔트로피 높은" 확장자(동영상/압축 등)
static const char *RANDOM_LIKE_EXTS[] = {
    "zip","7z","rar","gz","tgz","bz2",
    "mp4","mkv","avi","mov","wmv","flv","3gp","3g2",
    "mp3","wav","wma",
    "iso","vdi","vmdk","vmx",
    NULL
};

// 포맷 구조가 있는 바이너리(문서/DB 계열)
static const char *STRUCTURED_BIN_EXTS[] = {
    "pdf","hwp","hwpx","doc","docx","dot","dotx",
    "ppt","pptx",
    "xls","xlsx",
    "mdb","accdb",
    "db","dbf","sqlite","sqlite3","sqlitedb",
    "ost","pst","msg",
    NULL
};

typedef enum {
    EXT_KIND_TEXT = 0,
    EXT_KIND_STRUCTURED_BIN,
    EXT_KIND_RANDOM_LIKE,
    EXT_KIND_OTHER,
    EXT_KIND_MAX
} ext_kind_t;

static const char *KIND_NAME[EXT_KIND_MAX] = {
    "TEXT",
    "STRUCTURED_BIN",
    "RANDOM_LIKE",
    "OTHER"
};

static void get_lower_ext(const char *name, char *ext_out, size_t sz) {
    ext_out[0] = '\0';
    const char *p = strrchr(name, '.');
    if (!p) return;
    p++;
    size_t i = 0;
    while (*p && i + 1 < sz) {
        ext_out[i++] = (char)tolower((unsigned char)*p++);
    }
    ext_out[i] = '\0';
}

static ext_kind_t classify_ext_kind(const char *ext) {
    if (!ext || !*ext) return EXT_KIND_OTHER;

    for (int i = 0; TEXT_EXTS[i]; i++)
        if (strcmp(ext, TEXT_EXTS[i]) == 0) return EXT_KIND_TEXT;

    for (int i = 0; RANDOM_LIKE_EXTS[i]; i++)
        if (strcmp(ext, RANDOM_LIKE_EXTS[i]) == 0) return EXT_KIND_RANDOM_LIKE;

    for (int i = 0; STRUCTURED_BIN_EXTS[i]; i++)
        if (strcmp(ext, STRUCTURED_BIN_EXTS[i]) == 0) return EXT_KIND_STRUCTURED_BIN;

    return EXT_KIND_OTHER;
}

/**********************
 * χ² 계산
 **********************/
static double calculate_chi_square(const unsigned char *buf, size_t size) {
    if (size == 0 || size < CHI_MIN_SAMPLE_SIZE) return 0.0;

    long counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[ (unsigned char)buf[i] ]++;
    }

    double expected = (double)size / 256.0;
    double chi_sq = 0.0;

    for (int i = 0; i < 256; i++) {
        double diff = counts[i] - expected;
        chi_sq += (diff * diff) / expected;
    }

    return chi_sq;
}

/**********************
 * 통계 누적용
 **********************/
static struct {
    double sum_chi[EXT_KIND_MAX];
    long   cnt_files[EXT_KIND_MAX];      // 해당 kind에 속한 파일 수
    long   cnt_used_for_avg[EXT_KIND_MAX]; // chi>0(샘플 충분)인 파일 수
} g_stats;

/**********************
 * 파일 방문 콜백 (nftw)
 **********************/
static int handle_entry(const char *fpath,
                        const struct stat *sb,
                        int typeflag,
                        struct FTW *ftwbuf)
{
    (void)ftwbuf;

    if (typeflag != FTW_F) return 0; // 정규 파일만

    // 확장자 추출
    char ext[32];
    get_lower_ext(fpath, ext, sizeof(ext));
    ext_kind_t kind = classify_ext_kind(ext);

    // 파일 크기 확인
    off_t fsize = sb->st_size;
    if (fsize <= 0) {
        printf("%s\t%s\t%s\t%ld\tchi=0 (empty)\n",
               KIND_NAME[kind], ext[0] ? ext : "-", fpath, (long)fsize);
        g_stats.cnt_files[kind]++;
        return 0;
    }

    // 샘플 크기 제한
    size_t sample_size = (fsize > MAX_SAMPLE_BYTES) ? MAX_SAMPLE_BYTES : (size_t)fsize;

    FILE *fp = fopen(fpath, "rb");
    if (!fp) {
        perror(fpath);
        return 0; // 그냥 스킵
    }

    unsigned char *buf = (unsigned char*)malloc(sample_size);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "malloc failed for %s\n", fpath);
        return 0;
    }

    size_t nread = fread(buf, 1, sample_size, fp);
    fclose(fp);

    double chi = 0.0;
    if (nread >= CHI_MIN_SAMPLE_SIZE) {
        chi = calculate_chi_square(buf, nread);
    }

    free(buf);

    // per-file 출력
    printf("%s\t%s\t%s\tsize=%ld sample=%zu chi=%.2f%s\n",
           KIND_NAME[kind],
           ext[0] ? ext : "-",
           fpath,
           (long)fsize,
           nread,
           chi,
           (nread < CHI_MIN_SAMPLE_SIZE ? " (sample<MIN -> not used in avg)" : ""));

    // 통계 누적
    g_stats.cnt_files[kind]++;
    if (chi > 0.0) {
        g_stats.sum_chi[kind] += chi;
        g_stats.cnt_used_for_avg[kind]++;
    }

    return 0;
}

/**********************
 * main
 **********************/
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <directory>\n"
                "  지정한 디렉터리 아래의 파일을 재귀적으로 순회하며\n"
                "  확장자 유형별로 카이제곱(χ²) 값을 계산합니다.\n",
                argv[0]);
        return 1;
    }

    const char *root = argv[1];

    memset(&g_stats, 0, sizeof(g_stats));

    /*
     * nftw 옵션:
     *  - 16: 동시에 열 수 있는 디렉터리 depth(적당한 값)
     *  - FTW_PHYS: 심볼릭 링크 따라가지 않음
     */
    if (nftw(root, handle_entry, 16, FTW_PHYS) == -1) {
        perror("nftw");
        return 1;
    }

    printf("\n========== SUMMARY (by ext kind) ==========\n");
    for (int k = 0; k < EXT_KIND_MAX; k++) {
        long total = g_stats.cnt_files[k];
        long used  = g_stats.cnt_used_for_avg[k];
        double avg = (used > 0) ? (g_stats.sum_chi[k] / (double)used) : 0.0;

        printf("%-15s : files=%ld, used_for_avg=%ld, avg_chi=%.2f\n",
               KIND_NAME[k], total, used, avg);
    }

    printf("\nNOTE:\n");
    printf(" - 샘플 크기 < %d 바이트인 파일은 chi=0으로 표시하고 평균에서 제외했습니다.\n",
           CHI_MIN_SAMPLE_SIZE);
    printf(" - MAX_SAMPLE_BYTES=%d 바이트까지만 읽어서 계산합니다.\n",
           (int)MAX_SAMPLE_BYTES);

    return 0;
}
