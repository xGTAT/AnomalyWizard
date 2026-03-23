# Intelligent Network Anomaly Monitor (Simple Version)

Beginner-friendly Python project for monitoring outgoing network traffic and raising a desktop alert when there is a sudden spike to an unknown external IP.

## What this does

- Sniffs IP packets in real time using `scapy`.
- Tracks outgoing bytes per destination IP over the last 30 seconds.
- Sends a desktop notification when traffic to an unknown external IP crosses a threshold.

## Project files

- `monitor.py` -> main monitoring service
- `requirements.txt` -> Python dependencies
- `scripts/start_background.ps1` -> starts monitor in background on Windows

## 1) Install prerequisites (Windows)

1. Install Python 3.10+.
2. Install [Npcap](https://npcap.com/) and check "Install Npcap in WinPcap API-compatible Mode".
3. Open PowerShell as Administrator.

## 2) Install dependencies

```powershell
cd d:\AnomalyWizard
python -m pip install -r requirements.txt
```

## 3) Run the monitor (foreground)

```powershell
python monitor.py
```

Press `Ctrl + C` to stop.

## 4) Run as background service (simple)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_background.ps1
```

To stop it later:

```powershell
Get-Process pythonw | Stop-Process
```

## How anomaly detection works

- Window: 30 seconds
- Alert threshold: 250000 bytes to one destination IP in that window
- Alert cooldown: 60 seconds per destination IP

Edit these values in `monitor.py`:

- `WINDOW_SECONDS`
- `SPIKE_BYTES_THRESHOLD`
- `ALERT_COOLDOWN_SECONDS`
- `KNOWN_SAFE_IPS`

## Notes

- If no notification appears, check Windows notification settings.
- Some traffic patterns can create false positives; this is expected in a simple version.
