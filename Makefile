# ===========================
# Makefile for blue1 (FUSE3)
# ===========================

CC      := gcc
CFLAGS  := -Wall -Wextra -O2 $(shell pkg-config --cflags fuse3)
LDLIBS  := $(shell pkg-config --libs fuse3)
TARGET  := blue
SRC     := blue.c

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "🔧 Building $@ ..."
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)
	@echo "Build complete: $@"

run: $(TARGET)
	@echo "Running FUSE filesystem in foreground..."
	./$(TARGET) $$HOME/workspace/target

umount:
	@echo "Unmounting ~/workspace/target ..."
	@fusermount3 -u $$HOME/workspace/target || true

log:
	@echo "Showing last 20 lines of log..."
	@tail -n 20 $$HOME/myfs_log.txt || echo "No log found at $$HOME/myfs_log.txt"

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET)

.PHONY: all clean run umount log
