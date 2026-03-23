from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from network import get_wifi_snapshot


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="WfiAudit+")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
def status() -> dict:
    snapshot = get_wifi_snapshot()
    return {
        "project": "WfiAudit+",
        "mode": snapshot["mode"],
        "sensor": "windows-netsh-wifi-telemetry",
        "connected_network": snapshot["connected_network"],
        "telemetry": snapshot["telemetry"],
        "note": (
            "This build exposes real Wi-Fi telemetry from the host adapter. "
            "Standard Wi-Fi scans do not provide reliable human tracking or room reconstruction."
        ),
    }


@app.get("/api/inference")
def inference() -> dict:
    return get_wifi_snapshot()
