from fastapi.testclient import TestClient

from api.server import create_app


def test_fastapi_app_exposes_auth_and_health_endpoints() -> None:
    client = TestClient(create_app())

    token_response = client.post(
        "/api/v1/auth/token",
        json={"username": "admin", "password": "changeme"},
    )
    assert token_response.status_code == 200
    body = token_response.json()
    assert "access_token" in body

    health_response = client.get("/api/v1/health")
    assert health_response.status_code == 200
