import launcher


def test_launcher_starts_local_server_without_browser(monkeypatch) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(launcher, "port_is_available", lambda host, port: True)
    monkeypatch.setattr(
        launcher.uvicorn,
        "run",
        lambda application, **options: captured.update(app=application, **options),
    )

    exit_code = launcher.run(["--port", "8123", "--no-browser"])

    assert exit_code == 0
    assert captured["app"] is launcher.app
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8123
    assert captured["reload"] is False
    assert captured["workers"] == 1
    assert captured["lifespan"] == "off"


def test_launcher_reports_an_occupied_port(monkeypatch, capsys) -> None:
    monkeypatch.setattr(launcher, "port_is_available", lambda host, port: False)

    exit_code = launcher.run(["--port", "8000", "--no-browser"])

    assert exit_code == 1
    assert "already in use" in capsys.readouterr().err
