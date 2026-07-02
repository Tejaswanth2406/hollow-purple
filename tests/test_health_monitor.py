import time

from MAHORAGHA.health import (
    ComponentState,
    ComponentStatus,
    HealthBand,
    HealthMonitor,
)


def test_health_report_exposes_failed_components_for_explainability() -> None:
    monitor = HealthMonitor(default_timeout_s=0.1)

    monitor.register("api", lambda: ComponentStatus.healthy("api", "healthy"))
    monitor.register("worker", lambda: ComponentStatus.down("worker", "timed out"))

    report = monitor.check()

    assert report.band == HealthBand.RED
    assert [component.name for component in report.failed_components()] == ["worker"]

    payload = report.to_dict()
    assert payload["failed_components"][0]["name"] == "worker"
    assert payload["failed_components"][0]["state"] == ComponentState.DOWN.value


def test_timeout_probe_is_marked_down_and_tracked() -> None:
    monitor = HealthMonitor(default_timeout_s=0.01)

    def slow_probe() -> ComponentStatus:
        time.sleep(0.05)
        return ComponentStatus.healthy("slow")

    monitor.register("slow", slow_probe)
    report = monitor.check()

    assert report.components[0].state == ComponentState.DOWN
    assert monitor.consecutive_failures("slow") == 1
    assert monitor.history("slow")[0].state == ComponentState.DOWN
