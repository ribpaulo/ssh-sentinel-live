"""Cross-platform launcher for the packaged Mini-SIEM application.

The launcher starts FastAPI on the local machine only and opens the web
interface as soon as the server health check becomes available.
"""

import argparse
import multiprocessing
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Sequence

import uvicorn

from main import app


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
STARTUP_TIMEOUT_SECONDS = 15.0


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the launcher's command-line options."""

    parser = argparse.ArgumentParser(
        description="Start SSH Sentinel as a local web application.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Local HTTP port (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open a browser automatically after startup.",
    )
    return parser


def port_is_available(host: str, port: int) -> bool:
    """Check whether the requested local TCP port can be bound."""

    if not 1 <= port <= 65535:
        return False

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
    except OSError:
        return False
    return True


def wait_for_server_and_open(url: str, timeout: float = STARTUP_TIMEOUT_SECONDS) -> None:
    """Wait for the health check and then open the home page."""

    health_url = f"{url}/api/health"
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=0.5) as response:
                if response.status == 200:
                    webbrowser.open(url)
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)

    print(
        f"Note: the browser could not be opened automatically. Open {url} manually.",
        file=sys.stderr,
    )


def run(argv: Sequence[str] | None = None) -> int:
    """Validate options and start the local Uvicorn server."""

    args = build_argument_parser().parse_args(argv)
    if not 1 <= args.port <= 65535:
        print("Error: the port must be between 1 and 65535.", file=sys.stderr)
        return 2

    if not port_is_available(DEFAULT_HOST, args.port):
        alternative_port = args.port + 1 if args.port < 65535 else DEFAULT_PORT
        print(
            f"Error: port {args.port} is already in use. "
            f"For example, start the app with --port {alternative_port}.",
            file=sys.stderr,
        )
        return 1

    url = f"http://{DEFAULT_HOST}:{args.port}"
    if not args.no_browser:
        threading.Thread(
            target=wait_for_server_and_open,
            args=(url,),
            daemon=True,
            name="browser-opener",
        ).start()

    print(f"SSH Sentinel is running at {url}")
    print("Press Ctrl+C or close this window to stop.")

    # Explicit implementations avoid dynamic auto-selection and make the
    # PyInstaller build more reproducible on Linux and Windows.
    uvicorn.run(
        app,
        host=DEFAULT_HOST,
        port=args.port,
        loop="asyncio",
        http="h11",
        # The app defines no startup or shutdown hooks. Disabling lifespan also
        # keeps Ctrl+C shutdown of the packaged program free of warnings.
        lifespan="off",
        reload=False,
        workers=1,
    )
    return 0


if __name__ == "__main__":
    # On Windows, a frozen executable needs this call for modules that may use
    # multiprocessing support internally.
    multiprocessing.freeze_support()
    raise SystemExit(run())
