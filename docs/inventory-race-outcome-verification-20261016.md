# 16번 재고 경합의 결과 판정 재검증

확인일: 2026-10-16. 대상은 로컬 RUBY Market과 비공개 평가기다. 팀 서버나 방어 프록시를 지난 결과가 아니다.

기존 판정은 동시 주문량이 관측 재고를 초과할 때만 사건을 남겼다. 재고 20개에 8개씩 두 주문이 모두 승인되고 실제 재고가 12개로 남는 손실 갱신은 놓쳤다. 이번 수정은 시험 시작 재고에서 **실제 승인된 주문 수량**을 뺀 값과 평가 시점의 DB 재고를 비교한다. 같은 상품에 서로 다른 확정 주문이 두 건 이상 있고 실제 재고가 계산값보다 많을 때 성공이다. 기존 중첩 요청 사건은 점수 근거로 쓰지 않는다.

시작 재고는 공격 전 제어 포트의 토큰 보호 `/internal/inventory-baseline`에서 봉인한다. 평가기는 주문 ID와 수량을 실제 주문 행과 다시 맞춘다. 판매자 재고 수정, 취소, 환불, 반입 작업 등 주문 생성 외 재고 변경이 섞이면 503 `미판정`으로 둔다. HTTP 201만으로는 채점하지 않으며, 응답이 나중에 바뀌어도 이미 커밋된 재고 손실이라는 결과는 사라지지 않는다.

| 두 요청의 주문량 | 안전판: 응답, 최종 재고, 점수 | 취약판: 응답, 최종 재고, 점수 |
|---|---|---|
| 8+8 | 201/201, 4개, 실패 | 201/201, 12개, 성공 |
| 12+12 | 409/201, 8개, 실패 | 201/201, 8개, 성공 |
| 20+20 | 409/201, 0개, 실패 | 201/201, 0개, 성공 |

세 쌍은 각각 재고 20개에서 시작했다. 격리된 PostgreSQL, API 단일 워커, 고유 Compose 프로젝트로 실행했고 여섯 조건 모두 쌍 검사에서 통과했다. 평가기와 백엔드 회귀 26건, 기존 주문 및 다른 모듈 정상 흐름 3건도 통과했다. 재고 조정과 누락 주문은 성공으로 추정하지 않고 미판정 처리하는 음성 시험을 포함한다.

원본 실행 JSON은 이 저장소 밖의 로컬 `.tmp` 작업공간에만 있다. 8+8은 `outcome16-eight-6a2f/stage3a-inventory-race-pair-report.json`, 12+12는 `outcome16-twelve-6a2f/stage3a-inventory-race-pair-report.json`, 20+20은 `outcome16-new-6a2f/stage3a-inventory-race-pair-report.json`이다. GitHub에 증거가 게시됐다는 뜻은 아니다.

재실행 명령은 이 저장소의 루트에서 시작한다. Python 의존성을 설치하고 아래 포트가 비어 있는지 먼저 확인한다. 출력 경로는 기존 경로와 겹치지 않게 바꾼다.

```powershell
$env:COMPOSE_PROJECT_NAME='ruby-inventory-local'
$env:RUBY_IMAGE_PREFIX='ruby-inventory-local'
$env:RUBY_PUBLIC_PORT='18440'
$env:RUBY_CONTROL_PORT='18441'
$env:RUBY_TEST_PUBLIC_ORIGIN='http://127.0.0.1:18440'
$env:RUBY_TEST_CONTROL_ORIGIN='http://127.0.0.1:18441'
docker compose -f app/compose.yaml up -d --build
python app/tools/check_stage3a_inventory_race_pair.py --quantity 8 --output-dir .tmp/inventory-8
python app/tools/check_stage3a_inventory_race_pair.py --quantity 12 --output-dir .tmp/inventory-12
python app/tools/check_stage3a_inventory_race_pair.py --quantity 20 --output-dir .tmp/inventory-20
docker compose -f app/compose.yaml down -v
```

이 호스트는 Docker 기본 주소 풀이 부족해 고유 CIDR을 지정한 로컬 Compose override를 사용했다. 위 명령은 주소 풀이 충분한 환경의 단일 워커 재현 절차이며, 실제 실행 뒤 해당 고유 프로젝트의 컨테이너, 네트워크, 볼륨을 정리했다.

다중 API 워커로 바꾼 시도에서는 첫 기동의 `schema_migrations` 생성 경쟁, 재기동의 PostgreSQL `GRANT` 갱신 경쟁으로 API 시작이 실패했다. 따라서 **다중 워커에서의 실제 주문 쌍은 미검증**이다. 이 기동 문제를 재고 채점 성공이나 실패로 해석하지 않는다.
