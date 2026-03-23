from network import get_connected_network, get_wifi_snapshot


def main() -> None:
    snapshot = get_wifi_snapshot()

    assert "connected_network" in snapshot
    assert "environment" in snapshot
    assert "telemetry" in snapshot
    assert "audit" in snapshot
    assert "radar" in snapshot
    assert "tracked_objects" in snapshot
    assert "device" in snapshot["radar"]
    assert "scan_errors" in snapshot["telemetry"]
    assert "security_posture" in snapshot["audit"]
    assert snapshot["connected_network"] == get_connected_network()

    if snapshot["tracked_objects"]:
        assert "audit" in snapshot["tracked_objects"][0]["inspection"]
        assert "findings" in snapshot["tracked_objects"][0]["inspection"]["audit"]
        assert "snapshot" in snapshot["tracked_objects"][0]["inspection"]

    print("Smoke check passed.")
    print(snapshot["connected_network"])
    print(snapshot["environment"])
    print(snapshot["telemetry"])
    print(snapshot["audit"])


if __name__ == "__main__":
    main()
