// attack_iat_existing.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/types.h>

#define MAX_FILES   1024
#define WRITE_SIZE  1024   // 1KB씩 덧쓰기

static int collect_files(const char *dirpath, char paths[][PATH_MAX], int max_files) {
    DIR *dp = opendir(dirpath);
    if (!dp) {
        perror("opendir");
        return -1;
    }

    struct dirent *de;
    int count = 0;
    while ((de = readdir(dp)) != NULL) {
        // . .. 는 스킵
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        // 전체 경로 만들기
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dirpath, de->d_name);

        struct stat st;
        if (stat(full, &st) == -1)
            continue;

        // 일반 파일만 대상
        if (!S_ISREG(st.st_mode))
            continue;

        if (count < max_files) {
            strncpy(paths[count], full, PATH_MAX - 1);
            paths[count][PATH_MAX - 1] = '\0';
            count++;
        } else {
            break;
        }
    }
    closedir(dp);
    return count;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <target_dir> [loops]\n"
            "  예) %s $HOME/workspace/target 100\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *target_dir = argv[1];
    int loops = -1; // -1 = 무한 루프
    if (argc >= 3) {
        loops = atoi(argv[2]);
        if (loops <= 0) loops = -1;
    }

    char files[MAX_FILES][PATH_MAX];
    int file_count = collect_files(target_dir, files, MAX_FILES);
    if (file_count <= 0) {
        fprintf(stderr, "[-] 디렉터리 안에 쓸 수 있는 일반 파일이 없습니다: %s\n", target_dir);
        return 1;
    }

    printf("[*] IAT 테스트: 기존 파일 대상 3초 간격 write\n");
    printf("    target_dir = %s\n", target_dir);
    printf("    file_count = %d\n", file_count);
    printf("    interval   = 3 sec, write_size = %d bytes\n", WRITE_SIZE);
    printf("    loops      = %s\n\n", (loops == -1 ? "infinite" : "finite"));

    // 낮은 엔트로피 데이터 (모두 'A')
    unsigned char buf[WRITE_SIZE];
    memset(buf, 'A', sizeof(buf));

    int iter = 0;
    int idx  = 0; // 어느 파일을 쓸지 가리키는 인덱스

    while (1) {
        const char *path = files[idx];

        int fd = open(path, O_WRONLY | O_APPEND);   // 이미 있는 파일만 대상, 생성/트렁크 없음
        if (fd == -1) {
            perror("open");
        } else {
            ssize_t w = write(fd, buf, WRITE_SIZE);
            if (w != WRITE_SIZE) {
                if (w == -1) perror("write");
                else fprintf(stderr, "partial write: %zd\n", w);
            } else {
                fsync(fd);
                printf("[*] %d회차: %s 에 %d바이트 덧쓰기 완료\n",
                       iter + 1, path, WRITE_SIZE);
            }
            close(fd);
        }

        iter++;
        if (loops != -1 && iter >= loops) {
            printf("[*] 지정된 루프 횟수(%d) 완료, 종료\n", loops);
            break;
        }

        // 다음 파일로
        idx = (idx + 1) % file_count;

        sleep(3);  // 3초 간격
    }

    return 0;
}
