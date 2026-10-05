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


def test_only_web_joins_the_pipeline_network() -> None:
    services = load_compose()["services"]

    # web 은 탐지/방어 공유망(pipeline)에 ruby-web-target 으로 참여하고,
    # 벤치마크 프록시가 직접 도달하는 benchmark-edge 에도 참여한다.
    assert network_names(services["web"]) == {"pipeline", "edge", "benchmark-edge"}
    assert services["web"]["networks"]["pipeline"]["aliases"] == [
        "ruby-web-target"
    ]
    # pipeline 에 들어가는 서비스는 web 하나뿐이다. 벤치마크 대상/프록시는
    # 공유망을 거치지 않는 분리된 경로로만 서로 통신한다.
    assert all(
        "pipeline" not in network_names(service)
        for name, service in services.items()
        if name != "web"
    )


def test_benchmark_entry_is_isolated_from_the_pipeline() -> None:
    services = load_compose()["services"]

    # 벤치마크 대상(juice-shop)과 프록시는 benchmark-edge 에서만 묶이고
    # 탐지/방어 공유망(pipeline)에는 연결되지 않는다.
    assert network_names(services["juice-shop"]) == {"benchmark-edge"}
    assert network_names(services["benchmark-proxy"]) == {"benchmark-edge"}
    # 프록시만 호스트 포트를 연다.
    assert "ports" in services["benchmark-proxy"]
    assert "ports" not in services["juice-shop"]


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
