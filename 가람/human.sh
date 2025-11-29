#!/bin/bash

TARGET_FILE="$HOME/workspace/target/human_test.txt"

echo "[*] 쓰기 대상: $TARGET_FILE"
echo "[*] 사람처럼 한 줄씩 입력해봐. 종료하려면 Ctrl+D."

while true; do
    read -p "> " line || break   # 사람이 입력하고 엔터 칠 때까지 대기
    echo "$line" >> "$TARGET_FILE"
done

echo "[*] 종료"
