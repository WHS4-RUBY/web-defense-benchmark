# 서버 벤치마크 대상 선택

SSH 터널로 여는 관리자 화면에서 포트 80의 보호 대상을 선택합니다. 3020 포트는 두 대상을
탐지·방어 없이 직접 열어 원본 동작을 비교하는 별도 진입점입니다.

| 주소 | 용도 | 탐지·방어 기록 |
| --- | --- | --- |
| `http://127.0.0.1:8088/__detection/dashboard` | SSH 터널을 통한 현재 보호 대상 확인·변경, 탐지 대시보드 | 관리 요청은 기록 대상이 아님 |
| `http://127.0.0.1:8088/__defense/dashboard` | SSH 터널을 통한 방어 대시보드 | 관리 요청은 기록 대상이 아님 |
| `http://HOST/` | 선택한 대상에 공격·정상 요청 전송 | 기록됨 |
| `http://HOST:3020/` | 관리자·보호 경로 및 직접 접속 안내 | 기록되지 않음 |
| `http://HOST:3020/juice-shop/` | Juice Shop 직접 접속 | 기록되지 않음 |
| `http://HOST:3020/ruby-shop/` | RUBY Market 직접 접속 | 기록되지 않음 |
| `http://HOST:3021/` | Juice Shop 루트 URL, 다른 컴퓨터의 RUBY 대상 등록용 | 이 서버의 대시보드에는 기록되지 않음 |
| `http://HOST:3022/` | RUBY Market 루트 URL, 다른 컴퓨터의 RUBY 대상 등록용 | 이 서버의 대시보드에는 기록되지 않음 |

관리자 화면을 열려면 사용자 컴퓨터에서 SSH 터널을 먼저 실행합니다.

```bash
ssh -L 8088:127.0.0.1:8088 root@158.247.253.127
```

3020 선택 안내 페이지에는 현재 대상 상태나 로그인·전환 API가 없습니다.
직접 접속 링크를 누르는 동작도 보호 대상을 바꾸지 않습니다. Juice Shop과
RUBY Market은 의도적으로 취약한 테스트 대상이므로, 같은 Origin인 3020에서
관리자 세션을 사용하지 않도록 관리 기능을 서버의 loopback 포트 8088로
분리합니다. 8088은 외부에 직접 공개하지 않습니다.

## 사전 조건

- RUBY 스택이 대상 선택 API와 loopback 관리자 포트 8088을 제공하고
  `ruby_ai-defense-net` 공유 네트워크에서 실행 중이어야 합니다. 다른 네트워크
  이름을 쓰면 `RUBY_BENCHMARK_PIPELINE_NETWORK`를 동일하게 설정합니다.
- RUBY의 대상 목록에 `ruby-shop`과 `juice-shop`이 등록돼 있어야 합니다.
  이 저장소는 같은 공유망에서 `ruby-web-target:8080`과
  `juice-shop-target:3000`을 제공합니다.
- CI가 게시한 동일한 커밋 SHA의 벤치마크 이미지와 운영 비밀값을
  `app/.env.production`에 설정합니다. 실제 `.env` 파일은 커밋하지 않습니다.
- `RUBY_WEB_PUBLIC_ORIGIN`은 기본 브라우저 Origin으로 설정합니다. 직접 접속
  `:3020`, `:3022`와 보호 경로 `:80`을 사용할 때는 다른 Origin을
  `RUBY_WEB_PUBLIC_ORIGINS`에 추가합니다. 예를 들어 기본값을
  `http://158.247.253.127:3020`으로 둔다면 추가값은
  `http://158.247.253.127,http://158.247.253.127:3022`입니다. 배포
  워크플로는 현재 서버에 대해 이 세 Origin을 자동으로 설정합니다. 쉼표로
  구분한 정확한 HTTP(S) Origin만
  허용하며 경로나 와일드카드는 사용할 수 없습니다.

## 실행

`main`에 변경이 merge되면 CI가 테스트를 통과하고 이미지 8개를 모두 GHCR에
게시한 다음, 동일한 커밋 SHA로 서버 배포를 자동 실행합니다. PR과 기능 브랜치
push는 서버에 배포하지 않습니다. 이전 SHA를 다시 배포해야 할 때만 GitHub
Actions의 `Deploy` 워크플로를 수동 실행하고, 이미 게시된 40자리 SHA를
`image_tag`에 입력합니다. 오래된 CI가 나중에 끝나더라도 현재 `main`과 다른
SHA라면 자동 배포를 건너뜁니다.

서버에서 수동으로 실행할 경우에는 이 저장소 루트에서 다음 명령을 사용합니다.
RUBY 스택을 먼저 올려 공유 네트워크를 만들어야 합니다.

```bash
docker compose --env-file app/.env.production -f app/compose.production.yaml config --quiet
docker compose --env-file app/.env.production -f app/compose.production.yaml pull
docker compose --env-file app/.env.production -f app/compose.production.yaml up -d --wait
```

기본 호스트 바인드는 `0.0.0.0:3020`, `:3021`, `:3022`입니다. 변경하려면
`BENCHMARK_PROXY_BIND`, `BENCHMARK_PROXY_PORT`, `BENCHMARK_JUICE_ROOT_PORT`,
`BENCHMARK_RUBY_ROOT_PORT`를 설정합니다. 운영 서버의 호스트·클라우드
방화벽에서도 원격 설치 컴퓨터가 사용할 포트를 허용해야 합니다. 배포 워크플로는
Compose 파일과 같은 커밋의 이미지를 사용합니다. 로컬 개발용
`app/compose.yaml`은 독립적인 `pipeline` 네트워크를 생성하므로, RUBY
스택과 연결된 운영 배포 경로를 검증하려면 `app/compose.production.yaml`의
외부 네트워크 구성을 사용해야 합니다.

종료할 때는 다음 명령을 사용합니다. 데이터까지 지울 때만 `--volumes`를
추가합니다.

```bash
docker compose --env-file app/.env.production -f app/compose.production.yaml down
```

## 실험 기록과 격리

다른 컴퓨터에 RUBY를 설치해 이 서버를 대상으로 삼을 때는 경로 프리픽스가 없는
`http://HOST:3021` 또는 `http://HOST:3022`를 대상 URL로 지정합니다. 예를 들어
Juice Shop과 RUBY Market을 둘 다 등록하려면 설치할 컴퓨터의 `TARGET_CHOICES`에
`juice-shop=http://HOST:3021,ruby-shop=http://HOST:3022`를 설정합니다.
`http://HOST:3020/juice-shop/` 같은 프리픽스 URL은 SPA의 리소스/API 경로가
겹치므로 원격 Defense 대상 URL로 사용하지 않습니다. 원격 컴퓨터에서 LLM
공격은 **그 컴퓨터의 Detection 공개 주소**로 보내야 그 컴퓨터의 탐지·방어
대시보드에 요청이 기록됩니다. `:3021`과 `:3022`에 직접 보낸 요청은
RUBY 파이프라인을 통과하지 않습니다. 원격 설치 컴퓨터의 보호 주소가 새로운
브라우저 Origin이라면, RUBY Market에서 Origin을 검사하는 일반 역할 변경
폼을 사용하기 전에 그 정확한 Origin을 운영 서버의 `RUBY_WEB_PUBLIC_ORIGINS`에
등록해야 합니다. GitHub Actions 배포를 사용한다면 `benchmark-server` 환경의
`RUBY_WEB_EXTRA_PUBLIC_ORIGINS` 변수에 쉼표로 구분해 등록하면 다음 배포의
`.env`에 포함됩니다. LLM이 HTTP로 보내는 대부분의 API 요청과 별개인 브라우저
폼 제약입니다.

관리자 화면에서 보호 대상을 선택한 뒤 공격자는 **포트 80** 주소로 요청해야
Detection과 Defense 대시보드에 기록됩니다. 두 대시보드의 요청 ID로 같은
요청을 연결할 수 있습니다. 대상 전환 시 생성되는 실험 실행 ID와 설정 시각은
관리자 화면에서 확인합니다. 기존 기록과 Detection의 누적 탐지 상태가
전환만으로 초기화되지는 않으므로, 실험 비교 시 실행 ID와 시각을 확인하고
필요한 초기화 절차를 별도로 진행합니다.

`web`과 `juice-shop`만 RUBY 공유망에 연결됩니다. `benchmark-proxy`는
`benchmark-edge`에만 연결되고 관리망에는 접근하지 않습니다. API, 평가기,
데이터 서비스는 호스트 포트를 열지 않습니다. 3020·3021·3022의 취약한
테스트 대상은 외부에 직접 공개됩니다. 3020·3022의 RUBY Market과 포트 80에
선택된 RUBY Market은 같은 `web` 및 데이터 서비스를 사용하므로 동시 시험 시
상태가 섞일 수 있습니다.
