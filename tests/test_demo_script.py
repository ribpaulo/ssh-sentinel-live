import subprocess
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "demo_brute_force.sh"


def test_demo_script_rejects_missing_path_argument() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "Verwendung:" in result.stderr


def test_demo_script_only_appends_expected_synthetic_lines(tmp_path: Path) -> None:
    demo_log = tmp_path / "demo.log"
    demo_log.write_text("bestehende Zeile\n", encoding="utf-8")

    result = subprocess.run(
        ["bash", str(SCRIPT), str(demo_log)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = demo_log.read_text(encoding="utf-8").splitlines()

    assert result.returncode == 0
    assert "6 synthetische SSH-Fehlversuche" in result.stdout
    assert lines[0] == "bestehende Zeile"
    assert len(lines[1:]) == 6
    assert all("Failed password for invalid user" in line for line in lines[1:])
    assert all("203.0.113.50" in line for line in lines[1:])
    assert all("demo-host sshd[" in line for line in lines[1:])
    assert not any("Accepted" in line for line in lines[1:])
