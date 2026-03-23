from __future__ import annotations

import ipaddress
import importlib
import time
from collections import defaultdict, deque
from typing import Deque, DefaultDict, Tuple

from scapy.all import IP, sniff  # type: ignore

# Beginner-friendly knobs you can edit.
WINDOW_SECONDS = 30
SPIKE_BYTES_THRESHOLD = 250_000  # 250 KB sent to one IP in 30 seconds
ALERT_COOLDOWN_SECONDS = 60
KNOWN_SAFE_IPS = {
    # Add known external IPs here if needed, for example "8.8.8.8"
}

# Per destination IP: [(timestamp, packet_size_bytes), ...]
outgoing_traffic: DefaultDict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
last_alert_time: dict[str, float] = {}


def is_known_or_private(ip_text: str) -> bool:
    """Treat local/private addresses and manually allowed addresses as safe."""
    if ip_text in KNOWN_SAFE_IPS:
        return True

    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_link_local
        or ip.is_reserved
    )


def send_alert(ip_text: str, total_bytes: int) -> None:
    title = "Potential Network Threat"
    message = (
        f"Unusual outgoing traffic detected: {total_bytes} bytes sent to {ip_text} "
        f"in the last {WINDOW_SECONDS} seconds."
    )

    print(f"[ALERT] {message}")

    try:
        notification = importlib.import_module("plyer.notification")
        notification.notify(
            title=title,
            message=message,
            app_name="Anomaly Monitor",
            timeout=10,
        )
    except Exception:
        # Notification library can fail if not installed or OS blocks popups.
        pass


def analyze_packet(packet) -> None:
    if IP not in packet:
        return

    dst_ip = packet[IP].dst
    packet_size = len(packet)
    now = time.time()

    history = outgoing_traffic[dst_ip]
    history.append((now, packet_size))

    while history and now - history[0][0] > WINDOW_SECONDS:
        history.popleft()

    total_recent_bytes = sum(size for _, size in history)

    if is_known_or_private(dst_ip):
        return

    previous_alert = last_alert_time.get(dst_ip, 0.0)
    if total_recent_bytes >= SPIKE_BYTES_THRESHOLD and now - previous_alert >= ALERT_COOLDOWN_SECONDS:
        send_alert(dst_ip, total_recent_bytes)
        last_alert_time[dst_ip] = now


def main() -> None:
    print("Starting monitor... Press Ctrl+C to stop.")
    print("Tip: Run terminal as Administrator for packet sniffing on Windows.")

    try:
        sniff(filter="ip", prn=analyze_packet, store=False)
    except PermissionError:
        print("Permission denied. Start your terminal as Administrator.")
    except OSError as exc:
        print(f"Sniffing failed: {exc}")
        print("On Windows, install Npcap and enable WinPcap compatibility mode.")
    except KeyboardInterrupt:
        print("\nMonitor stopped by user.")


if __name__ == "__main__":
    main()
