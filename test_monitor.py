"""
Simple mock tests for AnomalyWizard's `monitor.py`.
Run with: python test_monitor.py

These tests simulate packets without requiring real network traffic.
"""

import sys
import types
import time

# If `scapy` isn't installed in the test environment, provide a lightweight shim
# so `monitor` can import `IP` and `sniff` without requiring the real package.
if 'scapy.all' not in sys.modules:
    scapy_all = types.ModuleType('scapy.all')
    scapy_all.IP = object()
    scapy_all.sniff = lambda *a, **k: None
    sys.modules['scapy'] = types.ModuleType('scapy')
    sys.modules['scapy.all'] = scapy_all

import monitor


class FakePacket:
    def __init__(self, dst: str, size: int):
        self._dst = dst
        self._size = size

    def __contains__(self, key):
        # monitor.IP is the scapy IP symbol used in monitor.py
        return key is monitor.IP or getattr(key, "__name__", None) == "IP"

    def __getitem__(self, key):
        # Return an object with a `dst` attribute
        return type("Dst", (), {"dst": self._dst})()

    def __len__(self):
        return self._size


def reset_state():
    monitor.outgoing_traffic.clear()
    monitor.last_alert_time.clear()


def test_alert_trigger():
    reset_state()
    old_send = monitor.send_alert
    calls = []

    def fake_send(ip_text, total_bytes):
        calls.append((ip_text, total_bytes))
        print(f"[TEST] send_alert({ip_text}, {total_bytes})")

    monitor.send_alert = fake_send
    old_threshold = monitor.SPIKE_BYTES_THRESHOLD
    monitor.SPIKE_BYTES_THRESHOLD = 1000

    try:
        pkt = FakePacket("1.2.3.4", 300)
        for _ in range(4):
            monitor.analyze_packet(pkt)
            time.sleep(0.01)

        print("Alert triggered:", bool(calls))
    finally:
        monitor.send_alert = old_send
        monitor.SPIKE_BYTES_THRESHOLD = old_threshold


def test_private_ip_ignored():
    reset_state()
    old_send = monitor.send_alert
    calls = []

    monitor.send_alert = lambda ip, total: calls.append((ip, total)) or print("[TEST] send_alert called for private ip")
    try:
        pkt = FakePacket("192.168.1.100", 2000)
        monitor.analyze_packet(pkt)
        print("Private IP alerted:", bool(calls))
    finally:
        monitor.send_alert = old_send


def test_cooldown_behavior():
    reset_state()
    old_send = monitor.send_alert
    calls = []

    def fake_send(ip_text, total_bytes):
        calls.append((time.time(), ip_text, total_bytes))
        print(f"[TEST] send_alert({ip_text}, {total_bytes}) at {calls[-1][0]}")

    monitor.send_alert = fake_send
    old_threshold = monitor.SPIKE_BYTES_THRESHOLD
    old_cool = monitor.ALERT_COOLDOWN_SECONDS
    monitor.SPIKE_BYTES_THRESHOLD = 500
    monitor.ALERT_COOLDOWN_SECONDS = 60

    try:
        pkt = FakePacket("1.2.3.6", 300)
        for _ in range(2):
            monitor.analyze_packet(pkt)
            time.sleep(0.01)

        first_alerts = len(calls)

        # Immediately send more packets (should be suppressed by cooldown)
        for _ in range(2):
            monitor.analyze_packet(pkt)
            time.sleep(0.01)

        second_alerts = len(calls)
        print("Alerts before/after immediate repeat:", first_alerts, second_alerts)
    finally:
        monitor.send_alert = old_send
        monitor.SPIKE_BYTES_THRESHOLD = old_threshold
        monitor.ALERT_COOLDOWN_SECONDS = old_cool


if __name__ == "__main__":
    print("Running mock tests for AnomalyWizard...\n")
    test_alert_trigger()
    print()
    test_private_ip_ignored()
    print()
    test_cooldown_behavior()
    print("\nDone.")
