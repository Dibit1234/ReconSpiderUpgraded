from __future__ import annotations

import math
import platform
import re
import subprocess
import time
from collections import defaultdict, deque


class WifiTelemetryMonitor:
    def __init__(self) -> None:
        self.connected_signal_history: deque[int] = deque(maxlen=24)
        self.ap_signal_history: dict[str, deque[int]] = defaultdict(
            lambda: deque(maxlen=24)
        )

    def sample(self) -> dict:
        system = platform.system().lower()
        if system != "windows":
            return self._unsupported_platform(system)

        connected, interface_errors = _windows_connected_network()
        nearby_networks, scan_errors = _windows_visible_networks()

        all_errors = _dedupe_errors(interface_errors + scan_errors)
        permissions = {
            "needs_elevation": any(
                error["code"] == "needs-elevation" for error in all_errors
            ),
            "needs_location_permission": any(
                error["code"] == "needs-location-permission" for error in all_errors
            ),
            "can_read_connected_network": connected.get("ssid")
            not in (None, "Unavailable"),
            "can_scan_nearby_networks": bool(nearby_networks),
        }

        signal_quality = connected.get("signal_quality")
        if isinstance(signal_quality, int):
            self.connected_signal_history.append(signal_quality)

        for access_point in nearby_networks:
            ap_id = access_point["id"]
            quality = access_point.get("signal_quality")
            if isinstance(quality, int):
                self.ap_signal_history[ap_id].append(quality)

        stability_score = _stability_score(list(self.connected_signal_history))
        nearby_count = len(nearby_networks)
        same_channel_count = _same_channel_count(connected, nearby_networks)
        channel_congestion = _channel_congestion_score(nearby_count, same_channel_count)
        ssid_groups = _ssid_groups(nearby_networks)
        channel_groups = _channel_groups(nearby_networks)

        tracked_objects = [
            self._access_point_object(
                access_point,
                nearby_networks,
                ssid_groups,
                channel_groups,
                connected,
            )
            for access_point in nearby_networks[:20]
        ]
        summary = _summary_text(connected, nearby_count, same_channel_count, all_errors)
        status = "ok"
        if all_errors and nearby_networks:
            status = "limited"
        elif all_errors:
            status = "blocked"

        connected_audit = _connected_network_audit(
            connected,
            nearby_networks,
            list(self.connected_signal_history),
            channel_groups,
        )

        return {
            "timestamp": time.time(),
            "mode": "real-wifi-telemetry",
            "connected_network": connected,
            "environment": {
                "occupancy_score": round((signal_quality or 0) / 100, 2),
                "motion_score": round(stability_score, 2),
                "human_presence_likelihood": round(min(nearby_count / 12, 1.0), 2),
                "confidence": round(0.92 if status == "ok" else 0.62, 2),
                "summary": summary,
            },
            "telemetry": {
                "status": status,
                "permissions": permissions,
                "signal_history": list(self.connected_signal_history),
                "nearby_network_count": nearby_count,
                "same_channel_count": same_channel_count,
                "channel_congestion_score": round(channel_congestion, 2),
                "scan_errors": all_errors,
                "allowed_actions": [
                    "rescan",
                    "export-json",
                    "copy-bssid",
                    "passive-query-only",
                ],
            },
            "audit": connected_audit,
            "radar": _radar_map(nearby_networks),
            "tracked_objects": tracked_objects,
        }

    def _access_point_object(
        self,
        access_point: dict,
        nearby_networks: list[dict],
        ssid_groups: dict[str, list[dict]],
        channel_groups: dict[int, list[dict]],
        connected: dict,
    ) -> dict:
        history = list(self.ap_signal_history[access_point["id"]])
        channel = access_point.get("channel")
        band = access_point.get("band", "unknown")
        relative = _relative_position(access_point)
        audit = _access_point_audit(
            access_point,
            nearby_networks,
            history,
            ssid_groups,
            channel_groups,
        )
        history_stats = _history_stats(history)
        is_connected = (
            bool(connected.get("ssid"))
            and access_point.get("ssid") == connected.get("ssid")
            and access_point.get("channel") == connected.get("channel")
        )

        return {
            "id": access_point["id"],
            "label": access_point.get("ssid") or "Hidden network",
            "x": relative["x"],
            "y": relative["y"],
            "velocity_m_s": round(access_point.get("signal_quality", 0) / 100, 2),
            "confidence": round(access_point.get("signal_quality", 0) / 100, 2),
            "bssid": access_point.get("bssid"),
            "channel": channel,
            "band": band,
            "signal_quality": access_point.get("signal_quality"),
            "rssi_dbm": access_point.get("rssi_dbm"),
            "authentication": access_point.get("authentication"),
            "cipher": access_point.get("cipher"),
            "radio_type": access_point.get("radio_type"),
            "network_type": access_point.get("network_type"),
            "oui_prefix": _oui_prefix(access_point.get("bssid")),
            "connected_match": is_connected,
            "relative": relative,
            "tooltip": {
                "ssid": access_point.get("ssid") or "Hidden network",
                "signal_quality": access_point.get("signal_quality"),
                "channel": channel,
                "authentication": access_point.get("authentication") or "Unknown",
                "cipher": access_point.get("cipher") or "Unknown",
                "radio_type": access_point.get("radio_type") or "Unknown",
            },
            "inspection": {
                "dominant_direction": _trend_label(history),
                "room_context": f"{band} band",
                "heatmap": _signal_heatmap(history, access_point.get("signal_quality", 0)),
                "signal_history": history,
                "history_stats": history_stats,
                "pose": None,
                "audit": audit,
                "snapshot": {
                    "authentication": access_point.get("authentication") or "Unknown",
                    "cipher": access_point.get("cipher") or "Unknown",
                    "radio_type": access_point.get("radio_type") or "Unknown",
                    "network_type": access_point.get("network_type") or "Unknown",
                    "basic_rates": access_point.get("basic_rates") or "Unavailable",
                    "other_rates": access_point.get("other_rates") or "Unavailable",
                    "oui_prefix": _oui_prefix(access_point.get("bssid")) or "Unavailable",
                    "same_ssid_count": audit["snapshot"]["same_ssid_count"],
                    "same_channel_count": audit["snapshot"]["same_channel_count"],
                    "estimated_proximity": relative["distance_label"],
                    "approximation_note": "Relative placement is based on RSSI and deterministic channel/band spreading, not physical direction finding.",
                },
            },
        }

    @staticmethod
    def _unsupported_platform(system: str) -> dict:
        return {
            "timestamp": time.time(),
            "mode": "unsupported-platform",
            "connected_network": {
                "ssid": "Unavailable",
                "bssid": None,
                "source": f"{system}-unsupported",
            },
            "environment": {
                "occupancy_score": 0.0,
                "motion_score": 0.0,
                "human_presence_likelihood": 0.0,
                "confidence": 0.0,
                "summary": "Real Wi-Fi telemetry is only wired for Windows in this build.",
            },
            "telemetry": {
                "status": "blocked",
                "permissions": {
                    "needs_elevation": False,
                    "needs_location_permission": False,
                    "can_read_connected_network": False,
                    "can_scan_nearby_networks": False,
                },
                "signal_history": [],
                "nearby_network_count": 0,
                "same_channel_count": 0,
                "channel_congestion_score": 0.0,
                "scan_errors": [
                    {
                        "code": "unsupported-platform",
                        "message": "Real Wi-Fi telemetry is currently implemented for Windows only.",
                    }
                ],
                "allowed_actions": ["passive-query-only"],
            },
            "audit": {
                "overall_score": 0,
                "security_posture": "unavailable",
                "findings": [],
                "recommendations": [],
            },
            "radar": _radar_map([]),
            "tracked_objects": [],
        }


def get_wifi_snapshot() -> dict:
    return monitor.sample()


def get_connected_network() -> dict:
    return get_wifi_snapshot()["connected_network"]


def _windows_connected_network() -> tuple[dict, list[dict]]:
    output, errors = _run_netsh(["wlan", "show", "interfaces"])
    if output is None:
        return _unknown_network("windows-netsh-unavailable"), errors

    network = {
        "ssid": _match_first(r"^\s*SSID\s*:\s*(.+)$", output),
        "bssid": _match_first(r"^\s*BSSID\s*:\s*(.+)$", output),
        "state": _match_first(r"^\s*State\s*:\s*(.+)$", output),
        "radio_type": _match_first(r"^\s*Radio type\s*:\s*(.+)$", output),
        "authentication": _match_first(r"^\s*Authentication\s*:\s*(.+)$", output),
        "cipher": _match_first(r"^\s*Cipher\s*:\s*(.+)$", output),
        "channel": _safe_int(_match_first(r"^\s*Channel\s*:\s*(.+)$", output)),
        "receive_rate_mbps": _safe_float(
            _match_first(r"^\s*Receive rate \(Mbps\)\s*:\s*(.+)$", output)
        ),
        "transmit_rate_mbps": _safe_float(
            _match_first(r"^\s*Transmit rate \(Mbps\)\s*:\s*(.+)$", output)
        ),
        "signal_quality": _safe_percent(_match_first(r"^\s*Signal\s*:\s*(.+)$", output)),
        "source": "windows-netsh",
    }

    if network["signal_quality"] is not None:
        network["rssi_dbm"] = _quality_to_rssi(network["signal_quality"])

    if not network["ssid"] or str(network.get("state", "")).lower() != "connected":
        return _unknown_network("windows-not-connected"), errors

    return network, errors


def _windows_visible_networks() -> tuple[list[dict], list[dict]]:
    output, errors = _run_netsh(["wlan", "show", "networks", "mode=bssid"])
    if output is None:
        return [], errors

    networks = []
    current_network_meta: dict[str, str | None] = {}
    current_ap: dict | None = None

    for raw_line in output.splitlines():
        stripped = raw_line.strip()

        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", stripped)
        if ssid_match:
            if current_ap:
                networks.append(current_ap)
                current_ap = None
            current_network_meta = {"ssid": ssid_match.group(1).strip() or "Hidden network"}
            continue

        network_type_match = re.match(r"^Network type\s*:\s*(.+)$", stripped)
        if network_type_match:
            current_network_meta["network_type"] = network_type_match.group(1).strip()
            continue

        auth_match = re.match(r"^Authentication\s*:\s*(.+)$", stripped)
        if auth_match:
            current_network_meta["authentication"] = auth_match.group(1).strip()
            continue

        encryption_match = re.match(r"^Encryption\s*:\s*(.+)$", stripped)
        if encryption_match:
            current_network_meta["cipher"] = encryption_match.group(1).strip()
            continue

        basic_rates_match = re.match(r"^Basic rates \(Mbps\)\s*:\s*(.+)$", stripped)
        if basic_rates_match:
            current_network_meta["basic_rates"] = basic_rates_match.group(1).strip()
            continue

        other_rates_match = re.match(r"^Other rates \(Mbps\)\s*:\s*(.+)$", stripped)
        if other_rates_match:
            current_network_meta["other_rates"] = other_rates_match.group(1).strip()
            continue

        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.+)$", stripped)
        if bssid_match:
            if current_ap:
                networks.append(current_ap)
            bssid = bssid_match.group(1).strip().lower()
            current_ap = {
                "id": bssid,
                "ssid": current_network_meta.get("ssid"),
                "bssid": bssid,
                "authentication": current_network_meta.get("authentication"),
                "cipher": current_network_meta.get("cipher"),
                "network_type": current_network_meta.get("network_type"),
                "basic_rates": current_network_meta.get("basic_rates"),
                "other_rates": current_network_meta.get("other_rates"),
                "source": "windows-netsh-scan",
            }
            continue

        if not current_ap:
            continue

        signal_match = re.match(r"^Signal\s*:\s*(.+)$", stripped)
        if signal_match:
            quality = _safe_percent(signal_match.group(1))
            current_ap["signal_quality"] = quality
            current_ap["rssi_dbm"] = (
                _quality_to_rssi(quality) if quality is not None else None
            )
            continue

        radio_match = re.match(r"^Radio type\s*:\s*(.+)$", stripped)
        if radio_match:
            current_ap["radio_type"] = radio_match.group(1).strip()
            continue

        channel_match = re.match(r"^Channel\s*:\s*(.+)$", stripped)
        if channel_match:
            channel = _safe_int(channel_match.group(1))
            current_ap["channel"] = channel
            current_ap["band"] = _band_from_channel(channel)
            continue

    if current_ap:
        networks.append(current_ap)

    networks.sort(key=lambda item: item.get("signal_quality") or 0, reverse=True)
    return networks, errors


def _run_netsh(args: list[str]) -> tuple[str | None, list[dict]]:
    try:
        output = subprocess.check_output(
            ["netsh", *args],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
        )
        return output, []
    except subprocess.CalledProcessError as exc:
        return None, _classify_netsh_error(exc.output or str(exc))
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return None, [{"code": "command-failed", "message": str(exc)}]


def _classify_netsh_error(output: str) -> list[dict]:
    errors = []
    lowered = output.lower()
    if "requires elevation" in lowered or "error 5" in lowered:
        errors.append(
            {
                "code": "needs-elevation",
                "message": "Windows requires this process to run elevated to read WLAN data.",
            }
        )
    if "location permission" in lowered or "location services" in lowered:
        errors.append(
            {
                "code": "needs-location-permission",
                "message": "Windows Location services must be enabled to scan nearby Wi-Fi networks.",
            }
        )
    if not errors:
        errors.append(
            {"code": "netsh-error", "message": output.strip() or "Unknown netsh error."}
        )
    return errors


def _connected_network_audit(
    connected: dict,
    nearby_networks: list[dict],
    history: list[int],
    channel_groups: dict[int, list[dict]],
) -> dict:
    findings = []
    recommendations = []

    security_grade = _security_grade(
        connected.get("authentication"), connected.get("cipher")
    )
    if security_grade["severity"] != "low":
        findings.append(
            _finding(
                security_grade["severity"],
                security_grade["title"],
                security_grade["detail"],
            )
        )
        recommendations.append(security_grade["recommendation"])

    channel = connected.get("channel")
    overlap_count = len(channel_groups.get(channel, [])) - 1 if channel else 0
    if overlap_count > 0:
        findings.append(
            _finding(
                "medium",
                "Co-channel contention observed",
                f"{overlap_count} nearby access point(s) share channel {channel}.",
            )
        )
        recommendations.append(
            "Consider moving the access point to a less crowded channel if performance is poor."
        )

    if connected.get("signal_quality") is not None and connected["signal_quality"] < 45:
        findings.append(
            _finding(
                "medium",
                "Weak connected signal",
                f"Current signal quality is {connected['signal_quality']}%, which may reduce throughput and roaming reliability.",
            )
        )
        recommendations.append(
            "Check placement, distance, and obstructions affecting the connected access point."
        )

    stability = _stability_score(history)
    if history and stability < 0.55:
        findings.append(
            _finding(
                "medium",
                "Signal stability is poor",
                "Connected network RSSI is fluctuating noticeably over recent samples.",
            )
        )
        recommendations.append(
            "Monitor interference sources and compare signal quality over a longer capture window."
        )

    if connected.get("receive_rate_mbps") and connected.get("transmit_rate_mbps"):
        rx_tx_gap = abs(connected["receive_rate_mbps"] - connected["transmit_rate_mbps"])
        if rx_tx_gap > 120:
            findings.append(
                _finding(
                    "low",
                    "Asymmetric link rates observed",
                    f"Receive and transmit rates differ by about {int(rx_tx_gap)} Mbps.",
                )
            )

    if not findings:
        findings.append(
            _finding(
                "low",
                "No immediate passive issues detected",
                "The connected network looks reasonable from the current passive telemetry snapshot.",
            )
        )

    return {
        "overall_score": max(0, 100 - _risk_points(findings)),
        "security_posture": _posture_from_findings(findings),
        "findings": findings,
        "recommendations": _dedupe_strings(recommendations),
    }


def _access_point_audit(
    access_point: dict,
    nearby_networks: list[dict],
    history: list[int],
    ssid_groups: dict[str, list[dict]],
    channel_groups: dict[int, list[dict]],
) -> dict:
    findings = []
    recommendations = []

    security_grade = _security_grade(
        access_point.get("authentication"), access_point.get("cipher")
    )
    if security_grade["severity"] != "low":
        findings.append(
            _finding(
                security_grade["severity"],
                security_grade["title"],
                security_grade["detail"],
            )
        )
        recommendations.append(security_grade["recommendation"])

    ssid = access_point.get("ssid") or "Hidden network"
    same_name = ssid_groups.get(ssid, [])
    if len(same_name) > 1:
        auth_mix = sorted(
            {
                f"{item.get('authentication') or 'Unknown'} / {item.get('cipher') or 'Unknown'}"
                for item in same_name
            }
        )
        severity = "medium" if len(auth_mix) > 1 else "low"
        findings.append(
            _finding(
                severity,
                "Duplicate SSID observed",
                f"{len(same_name)} access points advertise the SSID '{ssid}'. Security profiles seen: {', '.join(auth_mix)}.",
            )
        )
        if len(auth_mix) > 1:
            recommendations.append(
                "Review whether SSIDs with mismatched security settings are intentional or a possible misconfiguration."
            )

    channel = access_point.get("channel")
    same_channel = len(channel_groups.get(channel, [])) - 1 if channel else 0
    if same_channel > 0:
        severity = "medium" if same_channel >= 3 else "low"
        findings.append(
            _finding(
                severity,
                "Channel crowding detected",
                f"{same_channel} nearby access point(s) share channel {channel}.",
            )
        )
        recommendations.append(
            "Compare neighboring AP channel usage before selecting final AP placement or preferred band."
        )

    signal_quality = access_point.get("signal_quality")
    if signal_quality is not None and signal_quality < 35:
        findings.append(
            _finding(
                "medium",
                "Very weak signal",
                f"Signal quality is only {signal_quality}%, which may indicate edge-of-coverage or a distant AP.",
            )
        )
    elif signal_quality is not None and signal_quality > 85:
        findings.append(
            _finding(
                "low",
                "Strong local signal",
                f"Signal quality is {signal_quality}%, suggesting this AP is physically nearby.",
            )
        )

    if history and _stability_score(history) < 0.5:
        findings.append(
            _finding(
                "medium",
                "Signal fluctuates across samples",
                "Recent RSSI history shows noticeable instability for this access point.",
            )
        )
        recommendations.append(
            "Recheck this AP over a longer interval to separate transient noise from persistent interference."
        )

    radio_type = (access_point.get("radio_type") or "").lower()
    if radio_type and "802.11n" in radio_type and access_point.get("band") == "2.4 GHz":
        findings.append(
            _finding(
                "low",
                "Legacy radio profile observed",
                "This AP is advertising an 802.11n 2.4 GHz profile, which may be more interference-prone than newer bands.",
            )
        )

    if access_point.get("network_type") and "infrastructure" not in access_point["network_type"].lower():
        findings.append(
            _finding(
                "medium",
                "Non-infrastructure network type observed",
                f"Network type is reported as '{access_point['network_type']}'.",
            )
        )

    if not findings:
        findings.append(
            _finding(
                "low",
                "No immediate passive audit concerns",
                "This access point does not show obvious configuration or coexistence issues from the current snapshot.",
            )
        )

    return {
        "overall_score": max(0, 100 - _risk_points(findings)),
        "security_posture": _posture_from_findings(findings),
        "findings": findings,
        "recommendations": _dedupe_strings(recommendations),
        "snapshot": {
            "authentication": access_point.get("authentication") or "Unknown",
            "cipher": access_point.get("cipher") or "Unknown",
            "radio_type": access_point.get("radio_type") or "Unknown",
            "same_ssid_count": len(same_name),
            "same_channel_count": max(0, same_channel),
        },
    }


def _security_grade(authentication: str | None, cipher: str | None) -> dict:
    auth = (authentication or "Unknown").lower()
    enc = (cipher or "Unknown").lower()
    if "open" in auth:
        return {
            "severity": "high",
            "title": "Open network detected",
            "detail": "This access point appears to advertise an open network with no authentication.",
            "recommendation": "Use WPA2-Personal or WPA3-Personal unless the open network is deliberately isolated and monitored.",
        }
    if "wpa3" in auth:
        return {
            "severity": "low",
            "title": "Modern authentication observed",
            "detail": "This access point advertises WPA3-based authentication.",
            "recommendation": "Keep WPA3 enabled and review client compatibility before offering downgrade paths.",
        }
    if "wpa2" in auth:
        return {
            "severity": "low",
            "title": "WPA2 authentication observed",
            "detail": "This access point advertises WPA2-based authentication.",
            "recommendation": "Review whether WPA3 transition mode is practical for this environment.",
        }
    if "wep" in auth or "wep" in enc:
        return {
            "severity": "high",
            "title": "Weak legacy encryption observed",
            "detail": "WEP or a similarly outdated security profile appears to be in use.",
            "recommendation": "Retire legacy encryption and migrate the SSID to WPA2 or WPA3.",
        }
    return {
        "severity": "medium",
        "title": "Unknown or uncommon security profile",
        "detail": f"Authentication '{authentication or 'Unknown'}' with cipher '{cipher or 'Unknown'}' needs manual review.",
        "recommendation": "Verify the intended authentication and cipher combination against site standards.",
    }


def _finding(severity: str, title: str, detail: str) -> dict:
    return {"severity": severity, "title": title, "detail": detail}


def _risk_points(findings: list[dict]) -> int:
    weights = {"high": 35, "medium": 18, "low": 6}
    return min(90, sum(weights.get(item["severity"], 8) for item in findings))


def _posture_from_findings(findings: list[dict]) -> str:
    severities = {item["severity"] for item in findings}
    if "high" in severities:
        return "attention-needed"
    if "medium" in severities:
        return "review"
    return "good"


def _ssid_groups(nearby_networks: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for network in nearby_networks:
        groups[network.get("ssid") or "Hidden network"].append(network)
    return groups


def _channel_groups(nearby_networks: list[dict]) -> dict[int, list[dict]]:
    groups: dict[int, list[dict]] = defaultdict(list)
    for network in nearby_networks:
        channel = network.get("channel")
        if channel is not None:
            groups[channel].append(network)
    return groups


def _dedupe_errors(errors: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for error in errors:
        key = (error.get("code"), error.get("message"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(error)
    return unique


def _dedupe_strings(values: list[str]) -> list[str]:
    unique = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _radar_map(nearby_networks: list[dict]) -> dict:
    counts = defaultdict(int)
    for network in nearby_networks:
        counts[network.get("band", "unknown")] += 1

    return {
        "type": "device-centric-radar",
        "width": 100,
        "height": 100,
        "device": {"x": 50, "y": 50, "label": "This device"},
        "rings": [16, 28, 40],
        "sectors": [
            {
                "band": "2.4 GHz",
                "start_angle": 205,
                "end_angle": 335,
                "count": counts.get("2.4 GHz", 0),
            },
            {
                "band": "5 GHz",
                "start_angle": 20,
                "end_angle": 160,
                "count": counts.get("5 GHz", 0),
            },
            {
                "band": "6 GHz",
                "start_angle": 160,
                "end_angle": 205,
                "count": counts.get("6 GHz", 0),
            },
        ],
        "note": "AP positions are approximate relative placements derived from RSSI, channel, and deterministic sector spreading.",
    }


def _relative_position(access_point: dict) -> dict:
    signal = access_point.get("signal_quality") or 0
    band = access_point.get("band", "unknown")
    channel = access_point.get("channel") or 1
    bssid = access_point.get("bssid") or ""

    base_angle = {
        "2.4 GHz": 265,
        "5 GHz": 95,
        "6 GHz": 182,
    }.get(band, 45)
    hash_offset = (sum(ord(char) for char in bssid) % 56) - 28
    channel_offset = _channel_angle_offset(band, channel)
    angle_deg = base_angle + hash_offset + channel_offset
    angle_rad = math.radians(angle_deg)

    radius = 12 + (100 - signal) * 0.28
    x = 50 + math.cos(angle_rad) * radius
    y = 50 + math.sin(angle_rad) * radius

    return {
        "x": round(max(8, min(92, x)), 1),
        "y": round(max(8, min(92, y)), 1),
        "angle_deg": round(angle_deg % 360, 1),
        "radius": round(radius, 1),
        "distance_label": _distance_label(signal),
    }


def _channel_angle_offset(band: str, channel: int) -> float:
    if band == "2.4 GHz":
        return (channel - 7) * 4.2
    if band == "5 GHz":
        return (channel - 100) * 0.45
    if band == "6 GHz":
        return (channel - 117) * 0.18
    return 0.0


def _distance_label(signal: int) -> str:
    if signal >= 80:
        return "very near"
    if signal >= 65:
        return "near"
    if signal >= 45:
        return "mid-range"
    return "far"


def _history_stats(history: list[int]) -> dict:
    if not history:
        return {"samples": 0, "min": None, "max": None, "range": None}
    return {
        "samples": len(history),
        "min": min(history),
        "max": max(history),
        "range": max(history) - min(history),
    }


def _oui_prefix(bssid: str | None) -> str | None:
    if not bssid:
        return None
    parts = bssid.split(":")
    return ":".join(parts[:3]).upper() if len(parts) >= 3 else None


def _band_from_channel(channel: int | None) -> str:
    if channel is None:
        return "unknown"
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 196:
        return "5 GHz"
    if channel >= 197:
        return "6 GHz"
    return "unknown"


def _quality_to_rssi(quality: int | None) -> int | None:
    if quality is None:
        return None
    return int((quality / 2) - 100)


def _stability_score(history: list[int]) -> float:
    if len(history) < 2:
        return 0.5 if history else 0.0
    mean = sum(history) / len(history)
    variance = sum((value - mean) ** 2 for value in history) / len(history)
    std_dev = math.sqrt(variance)
    return max(0.0, min(1.0, 1 - (std_dev / 18)))


def _channel_congestion_score(nearby_count: int, same_channel_count: int) -> float:
    score = nearby_count * 0.06 + same_channel_count * 0.11
    return max(0.0, min(1.0, score))


def _same_channel_count(connected: dict, nearby_networks: list[dict]) -> int:
    channel = connected.get("channel")
    bssid = connected.get("bssid")
    if channel is None:
        return 0
    return sum(
        1
        for network in nearby_networks
        if network.get("channel") == channel and network.get("bssid") != bssid
    )


def _summary_text(
    connected: dict, nearby_count: int, same_channel_count: int, errors: list[dict]
) -> str:
    if errors:
        return "; ".join(error["message"] for error in errors)

    signal = connected.get("signal_quality")
    channel = connected.get("channel")
    if signal is None:
        return "Connected network detected, but signal quality is unavailable."

    return (
        f"Real Wi-Fi telemetry active. Connected signal is {signal}% on channel {channel}; "
        f"{nearby_count} nearby access points detected, {same_channel_count} sharing the same channel."
    )


def _signal_heatmap(history: list[int], current_signal: int) -> list[list[float]]:
    samples = history[-7:] if history else [current_signal]
    grid = []
    for row in range(7):
        row_values = []
        for col in range(7):
            sample = samples[min(col, len(samples) - 1)]
            baseline = sample / 100
            decay = max(0.18, 1 - abs(3 - row) * 0.22)
            row_values.append(round(max(0.0, min(1.0, baseline * decay)), 2))
        grid.append(row_values)
    return grid


def _trend_label(history: list[int]) -> str:
    if len(history) < 2:
        return "insufficient history"
    delta = history[-1] - history[0]
    if abs(delta) <= 2:
        return "stable signal"
    return "strengthening signal" if delta > 0 else "weakening signal"


def _match_first(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if not match:
        return None
    value = match.group(1).strip()
    return value if value else None


def _safe_percent(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"(\d+)", value)
    return int(match.group(1)) if match else None


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"-?\d+", value)
    return int(match.group(0)) if match else None


def _safe_float(value: str | None) -> float | None:
    if value is None:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", value)
    return float(match.group(0)) if match else None


def _unknown_network(source: str) -> dict:
    return {
        "ssid": "Unavailable",
        "bssid": None,
        "source": source,
    }


monitor = WifiTelemetryMonitor()
