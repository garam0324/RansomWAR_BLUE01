#!/bin/bash

# 마운트 지점 경로 설정
MOUNT_POINT="$HOME/workspace/target"

# 마운트 지점이 존재하는지 확인
if [ ! -d "$MOUNT_POINT" ]; then
    echo "오류: 마운트 지점을 찾을 수 없습니다: $MOUNT_POINT"
    exit 1
fi

echo "테스트를 시작합니다. 10초 이내에 3개의 파일을 생성하고 삭제합니다."
echo "--------------------------------------------------------"

# 테스트용 파일 이름
FILE1="$MOUNT_POINT/testfile_A"
FILE2="$MOUNT_POINT/testfile_B"
FILE3="$MOUNT_POINT/testfile_C"

# 1. 파일 생성 (create는 차단 로직이 없으므로 모두 성공해야 함)
echo "1. 파일 3개 생성 시도..."
touch "$FILE1"
touch "$FILE2"
touch "$FILE3"
ls -l "$MOUNT_POINT" | grep "testfile_"

echo ""
echo "2. 파일 3개 빠른 속도로 삭제 시도..."

# 2. 파일 삭제 (unlink 트리거)
# 셸 스크립트 자체가 하나의 PID로 실행됩니다.

rm "$FILE1"
echo "rm $FILE1 (1번째 시도)"

rm "$FILE2"
echo "rm $FILE2 (2번째 시도)"

# 여기서부터 임계값(2)을 초과할 수 있음
rm "$FILE3"
if [ $? -eq 0 ]; then
    echo "rm $FILE3 (3번째 시도) - 성공 (예상 실패)"
else
    # FUSE가 EPERM(-1)을 반환하면 셸은 'Operation not permitted' 오류 출력
    echo "rm $FILE3 (3번째 시도) - 차단됨 (예상 성공!)"
fi

echo "--------------------------------------------------------"
echo "테스트 완료."
ls -l "$MOUNT_POINT" | grep "testfile_"
echo ""
echo "로그 파일($HOME/myfs_log.txt)에서 'BLOCK' 'rate-limit' 메시지를 확인하세요."
