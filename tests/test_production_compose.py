from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "app" / "compose.production.yaml"

# 레지스트리 이미지로 배포되는 자체 웹 스택 서비스.
REGISTRY_SERVICES = {
    "postgres",
    "redis",
    "object-store",
    "mock-integration",
    "api",
    "worker",
    "evaluator",
    "web",
    # 벤치마크 전용 리버스 프록시도 CI 가 빌드한 이미지로 배포한다.
    "benchmark-proxy",
}

# 공용 이미지(digest 고정)로 그대로 실행하는 벤치마크 대상.
PUBLIC_IMAGE_SERVICES = {
    "juice-shop",
}

# 호스트 포트를 노출하는 유일한 서비스(분리된 벤치마크 진입점).
HOST_PORT_SERVICES = {
    "benchmark-proxy",
}


def load_compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def network_names(service: dict) -> set[str]:
    networks = service.get("networks", {})
    if isinstance(networks, list):
        return set(networks)
    return set(networks)


def test_production_compose_uses_registry_images_without_host_ports() -> None:
    compose = load_compose()
    services = compose["services"]

    assert set(services) == REGISTRY_SERVICES | PUBLIC_IMAGE_SERVICES

    for name, service in services.items():
        # 빌드 컨텍스트는 어떤 서비스에도 남기지 않는다(전부 이미지 배포).
        assert "build" not in service
        # 벤치마크 프록시만 호스트 포트를 노출한다.
        if name in HOST_PORT_SERVICES:
            assert "ports" in service
        else:
            assert "ports" not in service
        # 자체 웹 스택 이미지는 CI 레지스트리 태그를 쓴다. 공용 대상은 예외.
        if name in REGISTRY_SERVICES:
            assert service["image"].startswith("${RUBY_BENCHMARK_IMAGE_PREFIX:")
            assert service["image"].endswith(
                ":${RUBY_BENCHMARK_IMAGE_TAG:?Set RUBY_BENCHMARK_IMAGE_TAG}"
            )
        else:
            # 공용 대상은 digest 로 고정한다.
            assert "@sha256:" in service["image"]


def test_only_targets_join_the_pipeline_network() -> None:
    services = load_compose()["services"]

    # web 은 탐지/방어 공유망(pipeline)에 ruby-web-target 으로 참여하고,
    # 벤치마크 프록시가 직접 도달하는 benchmark-edge 에도 참여한다.
    assert network_names(services["web"]) == {"pipeline", "edge", "benchmark-edge"}
    assert services["web"]["networks"]["pipeline"]["aliases"] == [
        "ruby-web-target"
    ]
    # Defense 는 같은 외부 네트워크에서 대상 이름을 조회한다.
    assert network_names(services["juice-shop"]) == {"pipeline", "benchmark-edge"}
    assert services["juice-shop"]["networks"]["pipeline"]["aliases"] == [
        "juice-shop-target"
    ]
    # 3020 프록시는 취약한 대상과 같은 Origin 이므로 관리망에 연결하지 않는다.
    assert network_names(services["benchmark-proxy"]) == {"benchmark-edge"}
    assert all(
        "pipeline" not in network_names(service)
        for name, service in services.items()
        if name not in {"web", "juice-shop"}
    )


def test_only_benchmark_proxy_publishes_target_ports() -> None:
    services = load_compose()["services"]

    assert "ports" in services["benchmark-proxy"]
    assert "ports" not in services["juice-shop"]
    assert services["benchmark-proxy"]["ports"] == [
        "${BENCHMARK_PROXY_BIND:-0.0.0.0}:${BENCHMARK_PROXY_PORT:-3020}:8080",
        "${BENCHMARK_PROXY_BIND:-0.0.0.0}:${BENCHMARK_JUICE_ROOT_PORT:-3021}:8081",
        "${BENCHMARK_PROXY_BIND:-0.0.0.0}:${BENCHMARK_RUBY_ROOT_PORT:-3022}:8082",
    ]


def test_public_selector_never_proxies_management_routes() -> None:
    config = (ROOT / "app" / "benchmark-proxy" / "nginx.conf").read_text(
        encoding="utf-8"
    )
    assert "proxy_pass http://$detection" not in config
    assert "location = /__detection/api/" not in config
    assert "location ^~ /__detection/ {" in config
    assert "location ^~ /__defense/ { return 404; }" in config

    selector = (ROOT / "app" / "benchmark-proxy" / "selector.html").read_text(
        encoding="utf-8"
    )
    script = (ROOT / "app" / "benchmark-proxy" / "selector.js").read_text(
        encoding="utf-8"
    )
    assert 'href="/juice-shop/"' in selector
    assert 'href="/ruby-shop/"' in selector
    assert 'http://127.0.0.1:8088/__detection/dashboard' in script
    assert 'ssh -L 8088:127.0.0.1:8088 root@158.247.253.127' in selector
    assert 'protectedUrl.port = "80"' in script
    assert "fetch(" not in script


def test_remote_installer_urls_serve_targets_at_root() -> None:
    config = (ROOT / "app" / "benchmark-proxy" / "nginx.conf").read_text(
        encoding="utf-8"
    )
    # A prefix target URL would double SPA and API paths in Defense. The
    # additional listeners hand an entire root path to one target each.
    assert "listen 8081;" in config
    assert "listen 8082;" in config
    assert "proxy_pass http://$juice_shop;" in config
    assert "proxy_pass http://$ruby_shop;" in config
    assert "BENCHMARK_JUICE_ROOT_PORT=3021" in (
        ROOT / "app" / ".env.production.example"
    ).read_text(encoding="utf-8")
    assert "BENCHMARK_RUBY_ROOT_PORT=3022" in (
        ROOT / "app" / ".env.production.example"
    ).read_text(encoding="utf-8")


def test_evaluator_and_data_services_remain_private() -> None:
    compose = load_compose()
    services = compose["services"]

    assert compose["networks"]["pipeline"]["external"] is True
    assert all(
        compose["networks"][name]["internal"] is True
        for name in ("edge", "data", "control")
    )
    # benchmark-edge 는 프록시의 호스트 포트 노출을 위해 internal 이 아니다.
    # (값 없이 선언되면 YAML 에서 None 으로 파싱된다.)
    benchmark_edge = compose["networks"]["benchmark-edge"] or {}
    assert benchmark_edge.get("internal") is not True
    assert network_names(services["evaluator"]) == {"control"}
    assert network_names(services["api"]) == {"edge", "data"}
    assert network_names(services["postgres"]) == {"data", "control"}
    assert network_names(services["redis"]) == {"data"}
    assert network_names(services["object-store"]) == {"data"}
    assert all("/var/run/docker.sock" not in str(service) for service in services.values())


def test_production_secrets_have_no_development_fallbacks() -> None:
    services = load_compose()["services"]
    rendered = str(services)

    required_names = {
        "POSTGRES_PASSWORD",
        "POSTGRES_APP_PASSWORD",
        "POSTGRES_UNTRUSTED_PASSWORD",
        "POSTGRES_VERIFIER_PASSWORD",
        "RUBY_WEB_OBJECT_ACCESS_KEY",
        "RUBY_WEB_OBJECT_SECRET_KEY",
        "RUBY_WEB_RESET_TOKEN",
        "RUBY_EVALUATOR_TOKEN",
        "RUBY_WEB_OPERATIONS_DIAGNOSTIC_KEY",
    }
    assert all(f"${{{name}:?" in rendered for name in required_names)
    assert "development-only" not in rendered
    assert "ops_sk_live_" not in rendered
