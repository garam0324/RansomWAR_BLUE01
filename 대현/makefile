CC      := gcc
CFLAGS  := -Wall -Wextra -O2 $(shell pkg-config --cflags fuse3)



LDLIBS  := $(shell pkg-config --libs fuse3) -lm
TARGET  := blue1
SRC     := blue1.c

all: $(TARGET)

$(TARGET): $(SRC)
# 컴파일 명령 마지막에 $(LDLIBS)가 올 때 -lm이 적용됨
$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS) -lm

run: $(TARGET)
./$(TARGET)

umount:
@fusermount3 -u $(HOME)/workspace/target || true

log:
@tail -n 20 /tmp/ransomware_defense.log || echo "No log found at /tmp/ransomware_defense.log"

clean:
rm -f $(TARGET)

.PHONY: all clean run umount log