# 서버 벤치마크 대상 선택

`benchmark-proxy`는 Detection/Defense를 거치지 않는 별도 실험 진입점입니다. 이
저장소의 대상 분리 변경이 배포되면 3020 포트에서 두 대상을 경로로 고릅니다.

| 경로 | 대상 |
| --- | --- |
| `/` | 대상 선택 안내 |
| `/juice-shop/` | OWASP Juice Shop |
| `/ruby-shop/` | RUBY Market |

3020 포트의 동작은 80 포트 파이프라인의 Defense 전달 대상을 바꾸지 않습니다.
`ruby` 저장소의 대상 전환 Compose 오버레이는 현재 존재하지 않으므로, 이 문서의
과거 `docker-compose.target.*.yml` 명령은 사용할 수 없습니다. 80 포트로 대상을
전환하려면 `ruby` 저장소에서 Defense 대상 설정과 재생성 절차를 먼저 구현해야 합니다.

## 사전 조건

- `ruby` 스택의 파이프라인 네트워크가 실행 중이어야 합니다. 이 스택의
  `RUBY_BENCHMARK_PIPELINE_NETWORK`를 해당 네트워크 이름과 맞춥니다. 기본값은
  `ruby_ai-defense-net`입니다.
- CI가 게시한 동일한 커밋 SHA의 벤치마크 이미지와 실제 운영 비밀값을
  `app/.env.production`에 설정합니다. 실제 `.env` 파일은 커밋하지 않습니다.
- `RUBY_WEB_PUBLIC_ORIGIN`은 브라우저에서 사용하는 주소의 Origin으로 설정합니다.
  현재 API는 역할 변경 폼의 Origin을 단일 값과 비교합니다. 80과 3020은 서로 다른
  Origin이므로 두 경로에서 그 폼을 동시에 정상 사용하려면 별도 복수 Origin 지원이
  필요합니다.

## 벤치마크 진입점 실행

이 저장소 루트에서 실행합니다. 대상 분리 변경의 CI 이미지가 게시되기 전에는
`benchmark-proxy` 이미지가 없어 아래 절차를 완료할 수 없습니다.

```bash
docker compose --env-file app/.env.production -f app/compose.production.yaml config --quiet
docker compose --env-file app/.env.production -f app/compose.production.yaml pull
docker compose --env-file app/.env.production -f app/compose.production.yaml up -d --wait
```

기본 호스트 바인드는 `0.0.0.0:3020`입니다. 다른 주소나 포트가 필요하면
`BENCHMARK_PROXY_BIND`, `BENCHMARK_PROXY_PORT`를 변경합니다. 운영 배포
워크플로는 `app/compose.production.yaml`과 같은 커밋의 이미지를 사용합니다.

종료할 때는 다음 명령을 사용합니다. 데이터까지 지울 때만 `--volumes`를 추가합니다.

```bash
docker compose --env-file app/.env.production -f app/compose.production.yaml down
```

## 실험 격리

`web`만 80 포트 파이프라인 네트워크에 `ruby-web-target` 이름으로 연결됩니다.
`juice-shop`과 `benchmark-proxy`는 그 네트워크에 연결되지 않습니다. API, 평가기,
데이터 서비스는 호스트 포트를 열지 않습니다.

3020의 RUBY Market과 80에서 `ruby-web-target`을 선택했을 때의 RUBY Market은
같은 `web` 및 데이터 서비스를 사용합니다. 두 경로를 동시에 시험하면 상태가 섞일
수 있으므로 실행별 초기화나 격리 스택이 필요합니다. Detection의 누적 상태는
대상 전환 시 별도로 초기화해야 합니다. `X-Experiment-Run-ID`는 실행 기록을
구분하지만 상태를 초기화하지 않습니다.
