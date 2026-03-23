# WfiAudit+

Passive Wi-Fi audit console for real telemetry, device-centric radar review, and wireless environment visibility.

## What This Project Is

This project currently provides:

- A Python backend that exposes real Wi-Fi telemetry from the host machine.
- A browser UI that visualizes connected network status and nearby access points.
- Real Windows `netsh` collection for SSID, BSSID, channel, signal quality, and scan errors.
- Real passive audit findings for each discovered access point.
- A device-centric radar view that places APs approximately relative to the current device using RSSI.
- Safe one-click actions such as rescan, copy BSSID, and export the selected AP snapshot.
- Explicit reporting when Windows permissions block Wi-Fi scans.

## Important Constraint

A normal web browser cannot directly access low-level Wi-Fi signal data such as CSI
(Channel State Information) from the currently connected network. That means:

- The frontend can display real telemetry collected by the backend.
- The backend must gather Wi-Fi measurements from the host OS, a local agent, or
  dedicated hardware.
- Standard Windows Wi-Fi scans are enough for signal quality, channel, and nearby
  access points.
- Standard Windows Wi-Fi scans are not enough for reliable human tracking or room
  reconstruction.

## Current Architecture

- `app.py`: FastAPI server and API routes.
- `network.py`: Real Windows Wi-Fi telemetry collection and parsing.
- `static/index.html`: Browser app UI.
- `static/styles.css`: Styling for the dashboard.
- `static/app.js`: Frontend polling and rendering logic.
- `test_smoke.py`: Lightweight validation for telemetry and audit payloads.

## Run It

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the server:

```bash
uvicorn app:app --reload
```

4. Open:

```text
http://127.0.0.1:8000
```

## API

- `GET /api/status`
- `GET /api/inference`

## Windows Permissions

For full nearby-network scanning on Windows, the backend may need:

- An elevated shell
- Windows Location services enabled

The app now reports these blockers directly in the API under `telemetry.scan_errors`.

## Smoke Check

Once Python is available in your shell, you can verify import and syntax health:

```bash
python -m py_compile app.py network.py test_smoke.py
```

## What Is Real Now

- Connected SSID and BSSID when Windows exposes them
- Signal quality and approximate RSSI
- Channel and radio type
- Nearby access points from `netsh wlan show networks mode=bssid`
- Passive audit findings for:
  channel crowding
  duplicate SSIDs
  weak or legacy security profiles
  signal instability
- Passive AP metadata such as network type, radio type, basic rates, other rates, and OUI prefix when Windows exposes them
- Real scan permission failures from Windows

## What Is Not Real Yet

- Human tracking
- Room geometry reconstruction
- Device location estimation
- CSI-based motion sensing
- Active penetration testing or disruptive attack workflows

## Next Real-World Steps

To move beyond standard Wi-Fi telemetry, we would typically add:

- CSI-capable hardware integration.
- A calibration workflow for floor plan alignment.
- A model that uses real time-series RF measurements rather than simple scan snapshots.
- Explicit consent, privacy controls, and retention limits.
