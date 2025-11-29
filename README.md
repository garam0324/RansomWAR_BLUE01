# RansomWAR | BLUE01 [RansomShiled]
## [팀 프로젝트] 랜섬웨어 대응 FUSE 파일시스템 개발

> **단국대학교 사이버보안학과 시스템보안 팀 프로젝트**  
> FUSE 기반으로 랜섬웨어의 파일 암호화 및 위변조를 실시간 탐지·차단하는 파일시스템 구현

---

## 프로젝트 개요
- **프로젝트명:** RansomWAR_BLUE01
- **주제:** 랜섬웨어 대응 FUSE 파일시스템 개발
- **참여 인원:** 3명 (BLUE 1팀)
- **기간:** 2025-10-13 ~ 2025-11-28
- [**Notion 🔗**](https://www.notion.so/RansomWAR-BLUE01-1a346e976de948d886bc60b37a2f7689?source=copy_link)

---

## 팀 구성
| 이름 | 역할 |
|------|------|
| 고대현 | 팀장, 코드 작성 및 보완, 보고서 작성 |
| 김가람 | 코드 작성 및 보완, 발표 |
| 김준범 | 코드 작성 및 보완, ppt 제작 |

---

## 주요 기능
- 엔트로피 기반 방어
- 스냅샷 백업 및 복구
- 쿨다운 기능 (연속 쓰기 차단)
- I/O 리듬 분석 (rate limit 우회 방지)
- 화이트리스트 확장자
- 확장자, 매직넘버 기반 방어
- rate limit 기능
- 로그 파일 제공

---

## 개발 환경
- **Language:** C   
- **Framework:** FUSE (Filesystem in Userspace)  
- **OS:** Ubuntu 22.04 LTS    

---

## 실행 (Ubuntu)
```bash
make
make run
