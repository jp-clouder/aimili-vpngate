from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import proxy_server
import snapshot_utils

_import_data_dir = tempfile.TemporaryDirectory()
_original_data_dir = os.environ.get("VPNGATE_DATA_DIR")
os.environ["VPNGATE_DATA_DIR"] = _import_data_dir.name
try:
    import vpngate_manager as manager
finally:
    if _original_data_dir is None:
        os.environ.pop("VPNGATE_DATA_DIR", None)
    else:
        os.environ["VPNGATE_DATA_DIR"] = _original_data_dir


class FakeProcess:
    def __init__(self) -> None:
        self.running = True
        self.terminated = False

    def poll(self):
        return None if self.running else 0

    def terminate(self) -> None:
        self.terminated = True
        self.running = False

    def wait(self, timeout=None):
        self.running = False
        return 0

    def kill(self) -> None:
        self.running = False


def valid_snapshot_rows(rows: list[tuple[str, str, str]]) -> str:
    csv_rows = [
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
    ]
    for index, (ip, country_long, country_short) in enumerate(rows):
        config_text = (
            "client\n"
            "dev tun\n"
            "proto udp\n"
            f"remote {ip} 1194 udp\n"
            "resolv-retry infinite\n"
            "nobind\n"
            "<ca>\nCA\n</ca>\n"
            "<cert>\nCERT\n</cert>\n"
            "<key>\nKEY\n</key>\n"
        )
        config = base64.b64encode(config_text.encode("utf-8")).decode("ascii")
        csv_rows.append(
            f"vpn{index}.example,{ip},100,20,1000,{country_long},{country_short},1,{config}"
        )
    return "\n".join(csv_rows) + "\n"


def valid_snapshot(ip: str = "198.51.100.10") -> str:
    return valid_snapshot_rows([(ip, "Japan", "JP")])


class ManagerLogicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
            mock.patch.object(manager.vpn_utils, "DATA_DIR", root),
            mock.patch.object(manager.vpn_utils, "IP_CACHE_FILE", root / "ip_cache.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager.active_openvpn_process = None
        manager.pending_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.active_connection_cancel_event = None
        manager.is_connecting = False
        manager.consecutive_proxy_failures = 0
        manager.last_proxy_failure_node_id = ""
        manager.background_refill_thread = None
        manager.background_refill_cancel_event.clear()
        manager.active_sessions.clear()
        # Hot-standby dual tunnel state.
        manager.standby_openvpn_process = None
        manager.standby_openvpn_node_id = ""
        manager.active_tun_dev = manager.PRIMARY_TUN_DEV
        manager.standby_tun_dev = manager.STANDBY_TUN_DEV
        manager.standby_building = False
        manager.standby_cancel_event = None
        manager.vpn_utils.set_active_tun_dev(manager.PRIMARY_TUN_DEV)

    def tearDown(self) -> None:
        if manager.connection_attempt_lock.locked():
            manager.connection_attempt_lock.release()
        manager.background_refill_cancel_event.set()
        manager.background_refill_thread = None
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    def write_nodes(self, count: int) -> list[dict]:
        nodes = []
        for index in range(count):
            node_id = f"node-{index}"
            nodes.append(
                {
                    "id": node_id,
                    "ip": f"192.0.2.{index + 1}",
                    "remote_host": f"192.0.2.{index + 1}",
                    "remote_port": 1194,
                    "ping": index + 1,
                    "score": 1000 - index,
                    "config_text": "client\nremote 192.0.2.1 1194 udp\n",
                    "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
                    "probe_status": "not_checked",
                    "probed_at": 0,
                    "active": False,
                }
            )
        manager.write_json(manager.NODES_FILE, nodes)
        return nodes

    def test_node_probe_stops_after_target_batch(self) -> None:
        nodes = self.write_nodes(12)
        calls = []

        def fake_openvpn(config_file, **kwargs):
            calls.append(config_file)
            return True, "ready", None

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=3,
            )

        self.assertEqual(5, len(calls))
        self.assertEqual(5, len(results))
        stored = manager.read_nodes()
        self.assertEqual(5, sum(node.get("probe_status") == "available" for node in stored))
        self.assertEqual(7, sum(node.get("probe_status") == "not_checked" for node in stored))

    def test_ip_classification_separates_proxy_use_from_network_type(self) -> None:
        residential, residential_reason = manager.vpn_utils.classify_ip_type(
            {
                "isp": "Sony Network Communications Inc.",
                "org": "Sony Network Communications Inc.",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        )
        softether, softether_reason = manager.vpn_utils.classify_ip_type(
            {
                "isp": "SoftEther",
                "org": "SoftEther Corporation",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        )
        hosting, hosting_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": True, "hosting": True, "mobile": False}
        )
        mobile, mobile_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": False, "hosting": False, "mobile": True}
        )
        unknown, unknown_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": True, "hosting": False, "mobile": False}
        )

        self.assertEqual(("residential", "consumer_or_unclassified_network"), (residential, residential_reason))
        self.assertEqual(("hosting", "proxy_provider_datacenter"), (softether, softether_reason))
        self.assertEqual(("hosting", "hosting_flag"), (hosting, hosting_reason))
        self.assertEqual(("mobile", "mobile_flag"), (mobile, mobile_reason))
        self.assertEqual(("unknown", "missing_provider_data"), (unknown, unknown_reason))
        self.assertEqual("low", manager.vpn_utils.classification_confidence(unknown_reason))

    def test_ip_enrichment_reclassifies_legacy_cache_and_keeps_proxy_quality(self) -> None:
        ip = "118.240.250.95"
        manager.vpn_utils.IP_CACHE_FILE.write_text(
            json.dumps(
                {
                    ip: {
                        "ip_type": "hosting",
                        "quality": "proxy",
                        "cached_at": 9999999999,
                        "classification_version": 1,
                    }
                }
            ),
            encoding="utf-8",
        )
        api_result = [
            {
                "status": "success",
                "query": ip,
                "country": "Japan",
                "regionName": "Tokyo",
                "city": "Tokyo",
                "isp": "Sony Network Communications Inc.",
                "org": "Sony Network Communications Inc.",
                "as": "AS2527 Sony Network Communications Inc.",
                "asname": "Sony Network Communications Inc.",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        ]
        response = mock.MagicMock()
        response.read.return_value = json.dumps(api_result).encode("utf-8")
        response.__enter__.return_value = response
        node = {"id": "sony", "ip": ip}

        with mock.patch.object(manager.vpn_utils.urllib.request, "urlopen", return_value=response) as urlopen_mock:
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("residential", node["ip_type"])
        self.assertEqual("proxy", node["quality"])
        self.assertTrue(node["is_proxy"])
        self.assertFalse(node["is_hosting"])
        urlopen_mock.assert_called_once()
        cache = json.loads(manager.vpn_utils.IP_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual(manager.vpn_utils.IP_CLASSIFICATION_VERSION, cache[ip]["classification_version"])

    def test_ambiguous_datacenter_uses_secondary_source_and_geo_country(self) -> None:
        ip = "219.100.37.98"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Chiyoda",
            "isp": "SoftEther",
            "org": "SoftEther Corporation",
            "as": "AS36599 SoftEther",
            "asname": "SOFTETHER",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        secondary = mock.MagicMock()
        secondary.read.return_value = json.dumps({"is_datacenter": True, "is_vpn": True}).encode("utf-8")
        secondary.__enter__.return_value = secondary
        node = {"id": "softether", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, secondary],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("hosting", node["ip_type"])
        self.assertEqual("high", node["ip_type_confidence"])
        self.assertEqual("datacenter", node["quality"])
        self.assertTrue(node["is_hosting"])
        self.assertEqual(["ip-api.com", "ipapi.is"], node["ip_type_sources"])
        self.assertEqual("JP", node["geo_country_short"])

    def test_unverified_datacenter_conflict_becomes_unknown(self) -> None:
        ip = "203.0.113.10"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Tokyo",
            "isp": "Example VPS",
            "org": "Example VPS Hosting",
            "as": "AS64500 Example",
            "asname": "EXAMPLE",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        node = {"id": "ambiguous", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, TimeoutError("secondary unavailable")],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("unknown", node["ip_type"])
        self.assertEqual("low", node["ip_type_confidence"])
        strict = manager.apply_routing_filters([node], {"routing_mode": "auto", "routing_ip_type": "residential"})
        self.assertEqual([], strict)

    def test_missing_provider_data_uses_secondary_source_or_stays_unknown(self) -> None:
        ip = "203.0.113.11"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Tokyo",
            "isp": "",
            "org": "",
            "as": "",
            "asname": "",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        node = {"id": "missing-provider", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, TimeoutError("secondary unavailable")],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("unknown", node["ip_type"])
        self.assertEqual("provider_data_unverified", node["ip_type_reason"])
        self.assertEqual("low", node["ip_type_confidence"])
        strict = manager.apply_routing_filters(
            [node],
            {"routing_mode": "auto", "routing_ip_type": "residential"},
        )
        self.assertEqual([], strict)

    def test_strict_residential_filter_requires_medium_or_high_confidence(self) -> None:
        nodes = [
            {"id": "low", "ip_type": "residential", "ip_type_confidence": "low"},
            {"id": "medium", "ip_type": "residential", "ip_type_confidence": "medium"},
            {"id": "mobile", "ip_type": "mobile", "ip_type_confidence": "high"},
            {"id": "hosting", "ip_type": "hosting", "ip_type_confidence": "high"},
        ]

        strict = manager.apply_routing_filters(
            nodes,
            {"routing_mode": "auto", "routing_ip_type": "residential"},
        )

        self.assertEqual(["medium", "mobile"], [node["id"] for node in strict])

    def test_background_ip_enrichment_merges_metadata_without_replacing_status(self) -> None:
        nodes = self.write_nodes(2)
        nodes[0]["probe_status"] = "available"
        manager.write_json(manager.NODES_FILE, nodes)

        def fake_enrich(items):
            for item in items:
                item["ip_type"] = "residential"
                item["quality"] = "proxy"
                item["owner"] = "Consumer ISP"
                item["is_proxy"] = True

        with mock.patch.object(manager.vpn_utils, "enrich_ip_info", side_effect=fake_enrich):
            changed = manager.enrich_stored_nodes()

        stored = manager.read_nodes()
        self.assertGreater(changed, 0)
        self.assertEqual("available", next(node for node in stored if node["id"] == "node-0")["probe_status"])
        self.assertTrue(all(node["ip_type"] == "residential" for node in stored))

    def test_source_deadline_still_tries_official_http(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl=True, deadline_seconds=None):
            if url == manager.API_HTTPS_URL:
                raise manager.SourceDeadlineExceeded("slow official source")
            if url == manager.API_HTTP_URL:
                return csv_text
            raise AssertionError(f"unexpected source: {url}")

        with (
            mock.patch.object(manager, "fetch_api_text_with_deadline", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [manager.API_HTTPS_URL, manager.API_HTTP_URL],
            [call.args[0] for call in fetch_mock.call_args_list],
        )

    def test_probe_failure_preserves_existing_ip_metadata(self) -> None:
        nodes = self.write_nodes(1)
        nodes[0].update(
            {
                "owner": "Existing ISP",
                "location": "日本 东京",
                "ip_type": "residential",
                "ip_type_confidence": "medium",
            }
        )
        manager.write_json(manager.NODES_FILE, nodes)

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=0),
            mock.patch.object(manager, "run_openvpn_until_ready", return_value=(False, "offline", None)),
        ):
            manager.test_multiple_nodes([nodes[0]["id"]])

        stored = manager.read_nodes()[0]
        self.assertEqual("unavailable", stored["probe_status"])
        self.assertEqual("Existing ISP", stored["owner"])
        self.assertEqual("日本 东京", stored["location"])
        self.assertEqual("residential", stored["ip_type"])
        self.assertEqual("medium", stored["ip_type_confidence"])

    def test_country_matching_accepts_iso_and_legacy_name(self) -> None:
        node = {"country": "日本", "country_short": "JP"}
        self.assertTrue(manager.country_matches(node["country"], "JP", node["country_short"]))
        self.assertTrue(manager.country_matches(node["country"], "日本", node["country_short"]))
        self.assertFalse(manager.country_matches(node["country"], "KR", node["country_short"]))
        self.assertEqual("JP", manager.normalize_routing_country("日本", [node]))

    def test_web_and_proxy_ports_must_be_distinct(self) -> None:
        self.assertTrue(manager.ports_conflict(8787, "8787"))
        self.assertFalse(manager.ports_conflict(8787, 7928))

    def test_ui_connection_requires_tunnel_and_proxy_readiness(self) -> None:
        manager.active_openvpn_node_id = "node-1"
        manager.active_openvpn_process = FakeProcess()
        base_state = {"is_connecting": False, "tunnel_ready": True, "proxy_ready": False, "proxy_ok": False}
        self.assertFalse(manager.connection_ready_for_ui(base_state))
        ready_state = {**base_state, "proxy_ready": True, "proxy_ok": True}
        self.assertTrue(manager.connection_ready_for_ui(ready_state))

    def test_manual_disconnect_state_clears_all_readiness_flags(self) -> None:
        nodes = self.write_nodes(1)
        nodes[0]["active"] = True
        manager.write_json(manager.NODES_FILE, nodes)
        manager.set_state(
            is_connecting=True,
            tunnel_ready=True,
            proxy_ready=True,
            proxy_ok=True,
            proxy_ip="198.51.100.20",
        )

        with mock.patch.object(manager, "stop_active_openvpn") as stop_mock:
            manager.clear_active_connection_state("手动断开连接")

        stop_mock.assert_called_once_with()
        state = manager.get_state()
        self.assertFalse(state["is_connecting"])
        self.assertFalse(state["tunnel_ready"])
        self.assertFalse(state["proxy_ready"])
        self.assertFalse(state["proxy_ok"])
        self.assertEqual("-", state["proxy_ip"])
        self.assertFalse(any(node.get("active") for node in manager.read_nodes()))

    def test_set_state_is_write_behind_until_flush(self) -> None:
        manager.set_state(active_node_latency="12 ms", last_check_message="hi")
        # Visible to readers immediately (in-memory)...
        self.assertEqual("12 ms", manager.get_state()["active_node_latency"])
        # ...but not on disk until flush_state().
        on_disk = (
            json.loads(manager.STATE_FILE.read_text(encoding="utf-8"))
            if manager.STATE_FILE.exists()
            else {}
        )
        self.assertNotEqual("12 ms", on_disk.get("active_node_latency"))
        self.assertTrue(manager.flush_state())
        on_disk = json.loads(manager.STATE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("12 ms", on_disk["active_node_latency"])
        # A second flush with no changes writes nothing.
        self.assertFalse(manager.flush_state())

    def test_read_nodes_cache_invalidates_on_write(self) -> None:
        manager.write_json(manager.NODES_FILE, self.write_nodes(2))
        self.assertEqual(2, len(manager.read_nodes()))
        # In-process rewrite must be visible even within the same mtime tick.
        nodes = self.write_nodes(3)
        manager.write_json(manager.NODES_FILE, nodes)
        self.assertEqual(3, len(manager.read_nodes()))
        # External modification (bumped mtime) must also invalidate the cache.
        raw = json.loads(manager.NODES_FILE.read_text(encoding="utf-8"))
        raw.pop()
        manager.NODES_FILE.write_text(json.dumps(raw), encoding="utf-8")
        future_ns = time.time_ns() + 5_000_000_000
        os.utime(manager.NODES_FILE, ns=(future_ns, future_ns))
        self.assertEqual(2, len(manager.read_nodes()))

    def test_read_nodes_returns_isolated_copies(self) -> None:
        manager.write_json(manager.NODES_FILE, self.write_nodes(1))
        first = manager.read_nodes()
        first[0]["id"] = "mutated"
        self.assertNotEqual("mutated", manager.read_nodes()[0]["id"])

    def test_ui_config_cache_returns_isolated_copies(self) -> None:
        cfg = manager.load_ui_config()
        cfg["port"] = 9999
        self.assertNotEqual(9999, manager.load_ui_config()["port"])

    def test_hot_failover_swaps_tunnels_instantly(self) -> None:
        manager.write_json(manager.NODES_FILE, self.write_nodes(2))
        primary = FakeProcess()
        backup = FakeProcess()
        manager.active_openvpn_process = primary
        manager.active_openvpn_node_id = "node-0"
        manager.standby_openvpn_process = backup
        manager.standby_openvpn_node_id = "node-1"
        manager.vpn_utils.set_active_tun_dev("tun0")

        with (
            mock.patch.object(manager, "ensure_standby_connection"),
            mock.patch.object(
                manager, "_standby_tun_device_present", return_value=True
            ),
        ):
            self.assertTrue(manager.try_hot_failover("test"))

        # Roles swapped: the standby now serves traffic on its own device.
        self.assertIs(backup, manager.active_openvpn_process)
        self.assertEqual("node-1", manager.active_openvpn_node_id)
        self.assertIsNone(manager.standby_openvpn_process)
        self.assertEqual("", manager.standby_openvpn_node_id)
        self.assertEqual("tun1", manager.active_tun_dev)
        self.assertEqual("tun0", manager.standby_tun_dev)
        self.assertEqual("tun1", manager.vpn_utils.get_active_tun_dev())
        self.assertTrue(primary.terminated)  # dead primary reaped

        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertTrue(stored["node-1"]["active"])
        self.assertFalse(stored["node-1"].get("standby"))
        self.assertFalse(stored["node-0"]["active"])
        self.assertEqual("unavailable", stored["node-0"]["probe_status"])

        state = manager.get_state()
        self.assertEqual("node-1", state["active_openvpn_node_id"])
        self.assertEqual("tun1", state["active_tun_dev"])
        self.assertEqual("", state["standby_node_id"])
        self.assertEqual("none", state["standby_status"])

    def test_hot_failover_noop_without_healthy_standby(self) -> None:
        manager.write_json(manager.NODES_FILE, self.write_nodes(1))
        primary = FakeProcess()
        manager.active_openvpn_process = primary
        manager.active_openvpn_node_id = "node-0"
        manager.standby_openvpn_process = None
        manager.standby_openvpn_node_id = ""

        with mock.patch.object(manager, "ensure_standby_connection") as ensure_mock:
            self.assertFalse(manager.try_hot_failover("test"))
        ensure_mock.assert_not_called()

        self.assertIs(primary, manager.active_openvpn_process)
        self.assertEqual("node-0", manager.active_openvpn_node_id)
        self.assertEqual("tun0", manager.active_tun_dev)
        self.assertEqual("tun0", manager.vpn_utils.get_active_tun_dev())

    def test_hot_failover_or_cold_switch_prefers_hot(self) -> None:
        """热备健康时优先无感切换，不走冷切。"""
        with mock.patch.object(manager, "try_hot_failover", return_value=True) as hf_mock, \
             mock.patch.object(manager, "auto_switch_node") as cold_mock:
            manager.hot_failover_or_cold_switch("test-reason")
        hf_mock.assert_called_once_with("test-reason")
        cold_mock.assert_not_called()

    def test_hot_failover_or_cold_switch_falls_back_to_cold(self) -> None:
        """热备不可用时回落到冷切，行为与原来一致。"""
        with mock.patch.object(manager, "try_hot_failover", return_value=False) as hf_mock, \
             mock.patch.object(manager, "auto_switch_node") as cold_mock:
            manager.hot_failover_or_cold_switch("test-reason")
        hf_mock.assert_called_once_with("test-reason")
        cold_mock.assert_called_once_with()

    def test_ensure_standby_skips_when_hot_standby_disabled(self) -> None:
        with mock.patch.object(manager, "HOT_STANDBY_ENABLED", False):
            with mock.patch.object(manager, "connect_standby_node") as build_mock:
                manager.ensure_standby_connection()
        build_mock.assert_not_called()

    def test_ensure_standby_picks_node_other_than_primary(self) -> None:
        nodes = self.write_nodes(3)
        for n in nodes:
            n["probe_status"] = "available"
        manager.write_json(manager.NODES_FILE, nodes)
        manager.active_openvpn_process = FakeProcess()
        manager.active_openvpn_node_id = "node-0"
        picked: list[str] = []

        def fake_build(node_id: str, cancel_event=None) -> bool:
            picked.append(node_id)
            return True

        with mock.patch.object(manager, "connect_standby_node", side_effect=fake_build):
            manager.ensure_standby_connection()
        self.assertEqual(1, len(picked))
        self.assertNotEqual("node-0", picked[0])
        self.assertFalse(manager.standby_building)

    def test_setup_policy_routing_uses_per_device_table(self) -> None:
        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            return mock.Mock(returncode=0)

        with mock.patch.object(manager.subprocess, "run", side_effect=fake_run):
            self.assertTrue(manager.setup_policy_routing("tun1"))
        route_cmds = [c for c in calls if c[:3] == ["ip", "route", "add"]]
        self.assertTrue(route_cmds)
        self.assertIn("101", route_cmds[0])
        self.assertIn("tun1", route_cmds[0])
        rule_cmds = [c for c in calls if c[:3] == ["ip", "rule", "add"]]
        self.assertTrue(rule_cmds)
        self.assertIn("101", rule_cmds[0])

        calls.clear()
        with mock.patch.object(manager.subprocess, "run", side_effect=fake_run):
            self.assertTrue(manager.setup_policy_routing("tun0"))
        route_cmds = [c for c in calls if c[:3] == ["ip", "route", "add"]]
        self.assertIn("100", route_cmds[0])

    def test_ui_auth_json_is_written_private(self) -> None:
        auth_file = manager.DATA_DIR / "ui_auth.json"
        manager.write_json(auth_file, {"username": "test", "password": "secret"})
        if os.name != "nt":
            self.assertEqual(0o600, stat.S_IMODE(auth_file.stat().st_mode))

    def test_source_deadline_limits_total_fetch_time(self) -> None:
        def slow_fetch(url, verify_ssl=True):
            threading.Event().wait(0.1)
            return valid_snapshot()

        with mock.patch.object(manager, "fetch_api_text", side_effect=slow_fetch):
            started = manager.time.monotonic()
            with self.assertRaises(manager.SourceDeadlineExceeded):
                manager.fetch_api_text_with_deadline(
                    manager.API_HTTPS_URL,
                    deadline_seconds=0.01,
                )

        self.assertLess(manager.time.monotonic() - started, 0.08)

    def test_node_probe_stops_after_systemic_openvpn_failure(self) -> None:
        nodes = self.write_nodes(12)

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "[ERR_OVPN_TUN_NOT_AVAILABLE] missing TUN", None),
            ) as openvpn_mock,
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
            mock.patch.object(manager, "log_to_json"),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=3,
            )

        self.assertEqual(5, openvpn_mock.call_count)
        self.assertEqual(5, len(results))
        stored = manager.read_nodes()
        self.assertEqual(5, sum(node.get("probe_status") == "unavailable" for node in stored))
        self.assertEqual(7, sum(node.get("probe_status") == "not_checked" for node in stored))

    def test_maintenance_does_not_start_second_batch_after_systemic_failure(self) -> None:
        candidates = self.write_nodes(12)

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "[ERR_OVPN_CMD_NOT_FOUND] openvpn missing", None),
            ) as openvpn_mock,
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.maintain_valid_nodes()

        self.assertEqual(5, openvpn_mock.call_count)
        self.assertIn("Tested 5", result)

    def test_cancel_pending_connection_stops_handshake_process(self) -> None:
        process = FakeProcess()
        event = threading.Event()
        manager.pending_openvpn_process = process
        manager.active_connection_cancel_event = event
        manager.is_connecting = True
        previous_epoch = manager.connection_epoch

        manager.cancel_pending_connection_attempt()

        self.assertTrue(event.is_set())
        self.assertTrue(process.terminated)
        self.assertIsNone(manager.pending_openvpn_process)
        self.assertFalse(manager.is_connecting)
        self.assertEqual(previous_epoch + 1, manager.connection_epoch)

    def test_proxy_failures_reset_when_node_changes(self) -> None:
        self.assertEqual(1, manager.record_proxy_failure("node-a"))
        self.assertEqual(2, manager.record_proxy_failure("node-a"))
        self.assertEqual(1, manager.record_proxy_failure("node-b"))
        manager.reset_proxy_failure_counter("node-b")
        self.assertEqual(1, manager.record_proxy_failure("node-b"))

    def test_failed_switch_preflight_keeps_current_connection(self) -> None:
        nodes = self.write_nodes(2)
        nodes[0]["active"] = True
        manager.write_json(manager.NODES_FILE, nodes)
        current_process = FakeProcess()
        manager.active_openvpn_process = current_process
        manager.active_openvpn_node_id = nodes[0]["id"]

        with (
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "preflight failed", None),
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "已保留当前连接"):
                manager.connect_node(nodes[1]["id"])

        self.assertIs(manager.active_openvpn_process, current_process)
        self.assertEqual(nodes[0]["id"], manager.active_openvpn_node_id)
        self.assertTrue(current_process.running)
        stored = {node["id"]: node for node in manager.read_nodes()}
        self.assertEqual("unavailable", stored[nodes[1]["id"]]["probe_status"])

    def test_proxy_failure_does_not_report_connection_success(self) -> None:
        nodes = self.write_nodes(1)
        process = FakeProcess()

        with (
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(True, "ready", process),
            ),
            mock.patch.object(manager, "setup_policy_routing", return_value=False),
            mock.patch.object(manager, "cleanup_policy_routing"),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager, "check_proxy_health", return_value={"ok": False, "error": "no route"}),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "代理出口不可用"):
                manager.connect_node(nodes[0]["id"])

        self.assertFalse(process.running)
        self.assertIsNone(manager.active_openvpn_process)
        self.assertEqual("", manager.active_openvpn_node_id)
        stored = manager.read_nodes()
        self.assertEqual("unavailable", stored[0]["probe_status"])

    def test_manual_failure_recovery_prefers_previous_node(self) -> None:
        with (
            mock.patch.object(manager, "active_openvpn_running", return_value=False),
            mock.patch.object(manager, "connect_node", return_value="connected") as connect_mock,
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "auto_switch_node") as auto_switch_mock,
        ):
            manager.recover_after_manual_connect_failure("old-node")

        connect_mock.assert_called_once_with("old-node")
        auto_switch_mock.assert_not_called()

    def test_auto_switch_exhaustion_schedules_background_refill(self) -> None:
        with (
            mock.patch.object(manager, "schedule_background_refill", return_value=True) as schedule_mock,
            mock.patch.object(manager, "log_to_json") as log_mock,
        ):
            manager.auto_switch_node(attempt=3)

        schedule_mock.assert_called_once_with()
        log_mock.assert_called_once_with("INFO", "Main", "连续自动切换失败，已启动唯一后台节点补齐任务")

    def test_physical_interface_detection_is_cached(self) -> None:
        original_cache = manager.vpn_utils.physical_interface_cache
        manager.vpn_utils.physical_interface_cache = (None, 0.0)
        try:
            with mock.patch.object(
                manager.vpn_utils,
                "_detect_physical_interface",
                return_value="eth0",
            ) as detect_mock:
                self.assertEqual("eth0", manager.vpn_utils.get_physical_interface())
                self.assertEqual("eth0", manager.vpn_utils.get_physical_interface())
            detect_mock.assert_called_once_with()
        finally:
            manager.vpn_utils.physical_interface_cache = original_cache

    def test_forced_refresh_keeps_healthy_active_connection(self) -> None:
        process = FakeProcess()
        manager.active_openvpn_process = process
        manager.active_openvpn_node_id = "active-node"

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=[]),
            mock.patch.object(manager, "stop_active_openvpn") as stop_mock,
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.maintain_valid_nodes(force=True)

        self.assertEqual("没有拉取到新节点", result)
        self.assertTrue(process.running)
        stop_mock.assert_not_called()

    def test_fetch_timeout_skips_insecure_https_retry(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl):
            if url.startswith("https://"):
                raise TimeoutError("timed out")
            return csv_text

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "set_state"),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [mock.call(manager.API_HTTPS_URL, True), mock.call(manager.API_HTTP_URL, True)],
            fetch_mock.call_args_list,
        )

    def test_discovery_countries_are_normalized_and_persisted(self) -> None:
        countries = manager.persist_discovery_countries(["jp", "US", "JP", "bad", ""])

        self.assertEqual(["JP", "US"], countries)
        self.assertEqual(["JP", "US"], manager.load_ui_config()["discovery_countries"])
        self.assertEqual(["JP", "US"], manager.get_state()["discovery_countries"])

    def test_fetch_filters_country_after_source_is_accepted(self) -> None:
        csv_text = valid_snapshot_rows(
            [
                ("198.51.100.60", "Japan", "JP"),
                ("198.51.100.61", "United States", "US"),
            ]
        )
        manager.persist_discovery_countries(["JP"])

        with (
            mock.patch.object(manager, "fetch_api_text", return_value=csv_text) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(["JP"], [node["country_short"] for node in nodes])
        fetch_mock.assert_called_once_with(manager.API_HTTPS_URL, True)
        self.assertEqual(csv_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertIn("成功获取 2 个", manager.get_state()["last_fetch_message"])
        self.assertIn("保留 1 个", manager.get_state()["last_fetch_message"])

    def test_empty_country_result_does_not_fall_through_to_next_source(self) -> None:
        csv_text = valid_snapshot_rows(
            [
                ("198.51.100.70", "Japan", "JP"),
                ("198.51.100.71", "United States", "US"),
            ]
        )
        manager.persist_discovery_countries(["DE"])

        with (
            mock.patch.object(manager, "fetch_api_text", return_value=csv_text) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual([], nodes)
        fetch_mock.assert_called_once_with(manager.API_HTTPS_URL, True)
        state = manager.get_state()
        self.assertEqual("ok", state["last_fetch_status"])
        self.assertEqual("official_https", state["last_fetch_source"])
        self.assertIn("保留 0 个", state["last_fetch_message"])

    def test_node_table_contains_latency_country_panel_and_test_action(self) -> None:
        self.assertIn('<th style="width: 125px;">延迟</th>', manager.INDEX_HTML)
        self.assertIn('colspan="7"', manager.INDEX_HTML)
        self.assertIn('class="country-option-input"', manager.INDEX_HTML)
        self.assertIn('${testBtn}', manager.INDEX_HTML)

    def test_web_dashboard_has_browser_freeze_safeguards(self) -> None:
        self.assertNotIn("backdrop-filter", manager.LOGIN_HTML)
        self.assertNotIn("backdrop-filter", manager.INDEX_HTML)
        self.assertNotIn("background-attachment: fixed", manager.INDEX_HTML)
        self.assertIn("@media (prefers-reduced-motion: reduce)", manager.LOGIN_HTML)
        self.assertIn("@media (prefers-reduced-motion: reduce)", manager.INDEX_HTML)
        self.assertIn("const pageSize = 50;", manager.INDEX_HTML)
        self.assertIn('id="pagination_container"', manager.INDEX_HTML)
        self.assertIn('paginationContainer.style.display = totalPages > 1 ? "flex" : "none";', manager.INDEX_HTML)
        self.assertIn("const MAX_RENDERED_LOG_LINES = 300;", manager.INDEX_HTML)
        self.assertIn("nodesRequestPromise", manager.INDEX_HTML)
        self.assertIn("backgroundPollInFlight", manager.INDEX_HTML)
        self.assertIn('let lastNodesSnapshotSignature = "";', manager.INDEX_HTML)
        self.assertIn("if (signature === lastNodesSnapshotSignature) return false;", manager.INDEX_HTML)
        self.assertIn('typeof document.hidden !== "boolean" || !document.hidden', manager.INDEX_HTML)
        self.assertEqual(500, manager.WEB_LOG_MAX_ENTRIES)

    def test_web_dashboard_has_cross_browser_interaction_safeguards(self) -> None:
        self.assertNotIn("fonts.googleapis.com", manager.LOGIN_HTML)
        self.assertNotIn("fonts.googleapis.com", manager.INDEX_HTML)
        self.assertIn('const pwd = document.getElementById("password").value;', manager.LOGIN_HTML)
        self.assertIn('const password = $("cred_password").value;', manager.INDEX_HTML)
        self.assertIn("function fetchWithTimeout", manager.LOGIN_HTML)
        self.assertIn("function fetchWithTimeout", manager.INDEX_HTML)
        self.assertNotIn("await fetch(", manager.INDEX_HTML)
        self.assertIn('role="dialog" aria-modal="true"', manager.INDEX_HTML)
        self.assertIn('aria-label="关闭网页安全设置"', manager.INDEX_HTML)
        self.assertIn('class="option-card active" data-value="auto" aria-pressed="true"', manager.INDEX_HTML)
        self.assertNotIn('class="vps-recommend-tab"', manager.INDEX_HTML)
        self.assertNotIn('t.me/', manager.INDEX_HTML)
        self.assertNotIn('aff.php', manager.INDEX_HTML)
        self.assertIn('position: static;', manager.INDEX_HTML)
        self.assertIn('-webkit-overflow-scrolling: touch;', manager.INDEX_HTML)
        self.assertIn('formatUrlHost(window.location.hostname)', manager.INDEX_HTML)
        self.assertNotIn('id="status" class="status" style="display: none;"', manager.INDEX_HTML)
        self.assertIn('${esc(localProxy)}', manager.INDEX_HTML)
        self.assertIn('${esc(statusMessage)}', manager.INDEX_HTML)

    def test_dashboard_javascript_is_valid(self) -> None:
        if not shutil.which("node"):
            self.skipTest("Node.js is not installed; JavaScript syntax check skipped")
        scripts = re.findall(r"<script>(.*?)</script>", manager.INDEX_HTML, re.DOTALL)
        self.assertTrue(scripts)
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as handle:
            handle.write("\n".join(scripts))
            script_path = handle.name
        try:
            result = subprocess.run(
                ["node", "--check", script_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
        finally:
            Path(script_path).unlink(missing_ok=True)

    def test_random_password_uses_cryptographic_randomness(self) -> None:
        with mock.patch.object(manager.secrets, "choice", side_effect=list("aA0aA0aA0aA0")) as choice:
            password = manager.generate_random_password()

        self.assertEqual("aA0aA0aA0aA0", password)
        self.assertEqual(12, choice.call_count)

    def test_expired_sessions_are_removed(self) -> None:
        manager.active_sessions.update({"expired": 99.0, "active": 101.0})

        removed = manager.purge_expired_sessions(now=100.0)

        self.assertEqual(1, removed)
        self.assertEqual({"active": 101.0}, manager.active_sessions)

    def test_web_log_reader_only_returns_recent_valid_entries(self) -> None:
        log_file = manager.DATA_DIR / "logs" / "current.json"
        log_file.parent.mkdir(parents=True)
        with log_file.open("w", encoding="utf-8") as f:
            for index in range(520):
                f.write(json.dumps({"index": index}) + "\n")
            f.write("not-json\n")

        entries = manager.read_recent_log_entries(log_file)

        self.assertEqual(500, len(entries))
        self.assertEqual(20, entries[0]["index"])
        self.assertEqual(519, entries[-1]["index"])

    def test_web_update_check_removed_for_private_use(self) -> None:
        self.assertEqual("2.1.5", manager.APP_VERSION)
        self.assertEqual("V2.1.5 正式版", manager.APP_VERSION_LABEL)
        self.assertNotIn("检测更新", manager.INDEX_HTML)
        self.assertNotIn("/api/check_update", manager.INDEX_HTML)
        self.assertNotIn("checkForUpdate", manager.INDEX_HTML)
        self.assertNotIn("github.com/baoweise-bot", manager.INDEX_HTML)
        self.assertNotIn("api.github.com", manager.INDEX_HTML)
        self.assertFalse(hasattr(manager, "check_latest_release"))
        self.assertFalse(hasattr(manager, "GITHUB_LATEST_RELEASE_API"))
        self.assertIn('id="github_version_label"', manager.INDEX_HTML)

    def test_installer_updates_only_from_main(self) -> None:
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")

        self.assertIn('DEPLOY_BRANCH="main"', install_text)
        self.assertIn('branch = "main"', install_text)
        self.assertNotIn("CURRENT_BRANCH", install_text)
        self.assertNotIn("origin/master", install_text)
        self.assertNotIn("bate", install_text.lower())

    def test_installer_uses_secure_credentials_and_current_version(self) -> None:
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")

        self.assertNotIn("random.choices", install_text)
        self.assertIn("secrets.choice", install_text)
        self.assertIn('get_app_version()', install_text)
        self.assertNotIn("管理终端 v2.0", install_text)
        self.assertIn("5-90 秒", install_text)
        self.assertIn('new_pwd = input("请输入新管理密码 (不能为空): ")', install_text)
        self.assertIn('state["active_openvpn_node_id"] = ""', install_text)
        self.assertIn("ip link show dev tun0", install_text)
        self.assertIn("pidof openvpn", install_text)
        self.assertIn('chmod 600 "$AUTH_FILE"', install_text)
        self.assertIn("AIMILIVPN_NONINTERACTIVE", install_text)
        self.assertIn('["ip", "rule", "del", "table", "100"]', install_text)
        self.assertIn('/etc/sysctl.d/99-aimilivpn.conf', install_text)
        self.assertNotIn('http://[::1]:${PROXY_PORT}', install_text)

    def test_openvpn_command_requires_server_certificate_usage(self) -> None:
        with mock.patch.object(manager, "get_openvpn_version", return_value=2.5):
            command = manager.openvpn_command("node.ovpn", route_nopull=True)
        index = command.index("--remote-cert-tls")
        self.assertEqual("server", command[index + 1])

    def test_release_workflow_uses_full_patch_version(self) -> None:
        workflow_text = (manager.ROOT_DIR / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

        self.assertIn("default: v2.1.5", workflow_text)
        self.assertIn("AimiliVPN V$(tr -d '\\r\\n' < VERSION) 正式版", workflow_text)
        self.assertNotIn("cut -d. -f1,2 VERSION", workflow_text)

    def test_fetch_uses_github_mirror_after_official_sources(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl):
            if url == manager.MIRROR_HTTPS_URL:
                return csv_text
            raise TimeoutError("blocked")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "read_mirror_freshness", return_value=(0.0, "")),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [manager.API_HTTPS_URL, manager.API_HTTP_URL, manager.MIRROR_HTTPS_URL],
            [call.args[0] for call in fetch_mock.call_args_list],
        )
        self.assertEqual(csv_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("github_pages_https", manager.get_state()["last_fetch_source"])

    def test_http_source_does_not_replace_trusted_cache(self) -> None:
        cached_text = valid_snapshot("198.51.100.20")
        http_text = valid_snapshot("198.51.100.21")
        manager.API_CACHE_FILE.write_text(cached_text, encoding="utf-8")

        def fake_fetch(url, verify_ssl):
            if url == manager.API_HTTP_URL:
                return http_text
            raise TimeoutError("TLS unavailable")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.21", nodes[0]["ip"])
        self.assertEqual(cached_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))

    def test_fetch_falls_back_to_local_cache(self) -> None:
        cached_text = valid_snapshot("198.51.100.30")
        manager.API_CACHE_FILE.write_text(cached_text, encoding="utf-8")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=TimeoutError("all blocked")),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.30", nodes[0]["ip"])
        self.assertEqual("local_cache", manager.get_state()["last_fetch_source"])

    def test_bundled_snapshot_seeds_local_cache(self) -> None:
        bundled_text = valid_snapshot("198.51.100.40")
        manager.BUNDLED_SNAPSHOT_FILE.write_text(bundled_text, encoding="utf-8")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=TimeoutError("all blocked")),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.40", nodes[0]["ip"])
        self.assertEqual(bundled_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("bundled_initial", manager.get_state()["last_fetch_source"])

    def test_snapshot_rejects_executable_openvpn_directive(self) -> None:
        unsafe_config = (
            "client\ndev tun\nproto udp\nremote 198.51.100.50 1194 udp\n"
            "script-security 2\nup /tmp/payload\n"
            "<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
        )
        encoded = base64.b64encode(unsafe_config.encode("utf-8")).decode("ascii")
        csv_text = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n"
            f"vpn.example,198.51.100.50,100,20,1000,Japan,JP,1,{encoded}\n"
        )

        with self.assertRaisesRegex(ValueError, "no valid nodes"):
            snapshot_utils.parse_and_validate_snapshot(csv_text)


    def test_stop_active_openvpn_keep_standby_preserves_standby(self) -> None:
        """Manual switch must not flap a healthy standby tunnel."""
        active_proc = FakeProcess()
        standby_proc = FakeProcess()
        old = (
            manager.active_openvpn_process,
            manager.active_openvpn_node_id,
            manager.standby_openvpn_process,
            manager.standby_openvpn_node_id,
            manager.active_tun_dev,
            manager.standby_tun_dev,
        )
        manager.active_openvpn_process = active_proc
        manager.active_openvpn_node_id = "node-active"
        manager.standby_openvpn_process = standby_proc
        manager.standby_openvpn_node_id = "node-standby"
        manager.active_tun_dev = "tun0"
        manager.standby_tun_dev = "tun1"
        try:
            with (
                mock.patch.object(manager, "stop_standby_openvpn") as stop_sb_mock,
                mock.patch.object(manager, "cleanup_policy_routing") as cleanup_mock,
            ):
                manager.stop_active_openvpn(keep_standby=True)
            stop_sb_mock.assert_not_called()
            # only the active tunnel's table is flushed; standby keeps its own
            cleanup_mock.assert_called_once_with(tables={100})
            self.assertTrue(standby_proc.running)
            self.assertFalse(active_proc.running)
            self.assertEqual("node-standby", manager.standby_openvpn_node_id)
            self.assertIs(standby_proc, manager.standby_openvpn_process)
            # tunnel roles are left alone while the standby survives
            self.assertEqual("tun0", manager.active_tun_dev)
            self.assertEqual("tun1", manager.standby_tun_dev)
        finally:
            (
                manager.active_openvpn_process,
                manager.active_openvpn_node_id,
                manager.standby_openvpn_process,
                manager.standby_openvpn_node_id,
                manager.active_tun_dev,
                manager.standby_tun_dev,
            ) = old

    def test_stop_active_openvpn_default_still_kills_standby(self) -> None:
        """Default teardown keeps the old full-disconnect behavior."""
        active_proc = FakeProcess()
        standby_proc = FakeProcess()
        old = (
            manager.active_openvpn_process,
            manager.active_openvpn_node_id,
            manager.standby_openvpn_process,
            manager.standby_openvpn_node_id,
            manager.active_tun_dev,
            manager.standby_tun_dev,
        )
        manager.active_openvpn_process = active_proc
        manager.active_openvpn_node_id = "node-active"
        manager.standby_openvpn_process = standby_proc
        manager.standby_openvpn_node_id = "node-standby"
        manager.active_tun_dev = "tun1"
        manager.standby_tun_dev = "tun0"
        try:
            with mock.patch.object(manager, "cleanup_policy_routing") as cleanup_mock:
                manager.stop_active_openvpn()
            cleanup_mock.assert_called_once_with()
            self.assertFalse(standby_proc.running)
            self.assertEqual("", manager.standby_openvpn_node_id)
            self.assertEqual("tun0", manager.active_tun_dev)
            self.assertEqual("tun1", manager.standby_tun_dev)
        finally:
            (
                manager.active_openvpn_process,
                manager.active_openvpn_node_id,
                manager.standby_openvpn_process,
                manager.standby_openvpn_node_id,
                manager.active_tun_dev,
                manager.standby_tun_dev,
            ) = old

    def test_manual_switch_preserves_healthy_standby(self) -> None:
        """connect_node() to another node must leave a healthy standby alone."""
        nodes = self.write_nodes(3)
        active_proc = FakeProcess()
        standby_proc = FakeProcess()
        new_proc = FakeProcess()
        manager.active_openvpn_process = active_proc
        manager.active_openvpn_node_id = nodes[0]["id"]
        manager.standby_openvpn_process = standby_proc
        manager.standby_openvpn_node_id = nodes[2]["id"]
        try:
            with (
                mock.patch.object(
                    manager,
                    "run_openvpn_until_ready",
                    return_value=(True, "ready", new_proc),
                ),
                mock.patch.object(manager, "setup_policy_routing", return_value=True),
                mock.patch.object(manager, "cleanup_policy_routing"),
                mock.patch.object(manager, "stop_standby_openvpn") as stop_sb_mock,
                mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
                mock.patch.object(
                    manager,
                    "check_proxy_health",
                    return_value={"ok": True, "ip": "198.51.100.9", "latency_ms": 10},
                ),
                mock.patch.object(manager, "standby_healthy", return_value=True),
                mock.patch.object(manager, "ensure_standby_connection"),
                mock.patch.object(manager, "log_to_json"),
                mock.patch.object(manager, "validate_node_allowed_by_routing"),
            ):
                result = manager.connect_node(nodes[1]["id"])
            self.assertIn("Connected", result)
            self.assertEqual(nodes[1]["id"], manager.active_openvpn_node_id)
            stop_sb_mock.assert_not_called()
            self.assertTrue(standby_proc.running)
            self.assertIs(standby_proc, manager.standby_openvpn_process)
            self.assertEqual(nodes[2]["id"], manager.standby_openvpn_node_id)
        finally:
            manager.active_openvpn_process = None
            manager.active_openvpn_node_id = ""
            manager.standby_openvpn_process = None
            manager.standby_openvpn_node_id = ""

    def test_manual_switch_to_standby_node_rebuilds_standby(self) -> None:
        """Switching onto the standby node must drop it (no shadowing)."""
        nodes = self.write_nodes(2)
        active_proc = FakeProcess()
        standby_proc = FakeProcess()
        new_proc = FakeProcess()
        manager.active_openvpn_process = active_proc
        manager.active_openvpn_node_id = nodes[0]["id"]
        manager.standby_openvpn_process = standby_proc
        manager.standby_openvpn_node_id = nodes[1]["id"]
        try:
            with (
                mock.patch.object(
                    manager,
                    "run_openvpn_until_ready",
                    return_value=(True, "ready", new_proc),
                ),
                mock.patch.object(manager, "setup_policy_routing", return_value=True),
                mock.patch.object(manager, "cleanup_policy_routing"),
                mock.patch.object(manager, "stop_standby_openvpn") as stop_sb_mock,
                mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
                mock.patch.object(
                    manager,
                    "check_proxy_health",
                    return_value={"ok": True, "ip": "198.51.100.9", "latency_ms": 10},
                ),
                mock.patch.object(manager, "standby_healthy", return_value=True),
                mock.patch.object(manager, "ensure_standby_connection") as ensure_mock,
                mock.patch.object(manager, "log_to_json"),
                mock.patch.object(manager, "validate_node_allowed_by_routing"),
                mock.patch.object(manager.threading, "Thread") as thread_mock,
            ):
                result = manager.connect_node(nodes[1]["id"])
            self.assertIn("Connected", result)
            self.assertEqual(nodes[1]["id"], manager.active_openvpn_node_id)
            # standby shadowed the new active: torn down and scheduled for rebuild
            stop_sb_mock.assert_called_once_with()
            thread_mock.assert_called_once()
            ensure_mock.assert_not_called()  # runs in the background thread
        finally:
            manager.active_openvpn_process = None
            manager.active_openvpn_node_id = ""
            manager.standby_openvpn_process = None
            manager.standby_openvpn_node_id = ""

    def test_periodic_probe_excludes_standby_node(self) -> None:
        # Regression: the periodic probe must not open a second OpenVPN
        # session to the node the hot standby is already using — the
        # server may kick one of the duplicate sessions.
        nodes = self.write_nodes(4)
        nodes[0]["active"] = True
        nodes[1]["standby"] = True
        manager.write_json(manager.NODES_FILE, nodes)
        manager.active_openvpn_node_id = nodes[0]["id"]
        # The merge rebuilds the standby marker from the live process.
        manager.standby_openvpn_node_id = nodes[1]["id"]
        manager.standby_openvpn_process = FakeProcess()

        captured_ids: list[str] = []

        def fake_test_multiple(ids, **kwargs):
            captured_ids.extend(ids)
            return []

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=nodes),
            mock.patch.object(manager, "active_openvpn_running", return_value=True),
            mock.patch.object(manager, "test_multiple_nodes", side_effect=fake_test_multiple),
            mock.patch.object(manager, "log_to_json"),
        ):
            manager.maintain_valid_nodes()

        self.assertNotIn(nodes[1]["id"], captured_ids)
        self.assertIn(nodes[2]["id"], captured_ids)
        self.assertIn(nodes[3]["id"], captured_ids)
        manager.standby_openvpn_node_id = ""
        manager.standby_openvpn_process = None

    def test_standby_build_policy_routing_failure_is_logged(self) -> None:
        # Regression: every standby build failure path must leave a
        # log_to_json trail — print-only failures are invisible in the
        # on-disk JSON logs.
        nodes = self.write_nodes(2)
        standby_id = nodes[1]["id"]

        with (
            mock.patch.object(manager, "hot_standby_allowed", return_value=True),
            mock.patch.object(manager, "load_ui_config", return_value={}),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(True, "", FakeProcess()),
            ),
            mock.patch.object(manager, "setup_policy_routing", return_value=False),
            mock.patch.object(manager, "log_to_json") as log_mock,
        ):
            self.assertFalse(manager.connect_standby_node(standby_id))

        logged = " ".join(str(call.args) for call in log_mock.call_args_list)
        self.assertIn("策略路由", logged)

    def test_standby_build_failure_blacklists_node(self) -> None:
        # Regression (10-15 log): without a cooldown the builder retried
        # one dead node 345 times in 5.5 hours. A failed build must put
        # the node on the blacklist so the next round picks another one.
        nodes = self.write_nodes(2)
        standby_id = nodes[1]["id"]

        with (
            mock.patch.object(manager, "hot_standby_allowed", return_value=True),
            mock.patch.object(manager, "load_ui_config", return_value={}),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "handshake failed", None),
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            self.assertFalse(manager.connect_standby_node(standby_id))

        self.assertIn(standby_id, manager.load_blacklist())

    def test_standby_egress_failure_blacklists_node(self) -> None:
        nodes = self.write_nodes(2)
        standby_id = nodes[1]["id"]

        with (
            mock.patch.object(manager, "hot_standby_allowed", return_value=True),
            mock.patch.object(manager, "load_ui_config", return_value={}),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(True, "", FakeProcess()),
            ),
            mock.patch.object(manager, "setup_policy_routing", return_value=True),
            mock.patch.object(manager, "check_tunnel_health", return_value=False),
            mock.patch.object(manager, "log_to_json"),
        ):
            self.assertFalse(manager.connect_standby_node(standby_id))

        self.assertIn(standby_id, manager.load_blacklist())

    def test_auto_switch_skips_blacklisted_nodes(self) -> None:
        # Regression (10-16 07:30): auto-switch picked a node that had
        # just failed twice as a standby build. Blacklisted nodes must
        # not be switch candidates.
        nodes = self.write_nodes(3)
        dead_id = nodes[0]["id"]
        good_id = nodes[1]["id"]
        for n in nodes:
            n["probe_status"] = "available"
        manager.write_json(manager.NODES_FILE, nodes)
        manager.mark_blacklisted(nodes[0], "test failure")

        with (
            mock.patch.object(manager, "load_ui_config", return_value={}),
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(
                manager, "connect_node", return_value="connected"
            ) as connect_mock,
        ):
            manager.auto_switch_node()

        connect_mock.assert_called_once_with(good_id)

    def test_standby_build_primary_gone_is_logged(self) -> None:
        nodes = self.write_nodes(2)
        standby_id = nodes[1]["id"]

        with (
            mock.patch.object(manager, "hot_standby_allowed", return_value=True),
            mock.patch.object(manager, "load_ui_config", return_value={}),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(True, "", FakeProcess()),
            ),
            mock.patch.object(manager, "setup_policy_routing", return_value=True),
            mock.patch.object(manager, "check_tunnel_health", return_value=True),
            # Primary dies while the standby is being built.
            mock.patch.object(manager, "active_openvpn_running", return_value=False),
            mock.patch.object(manager, "log_to_json") as log_mock,
        ):
            self.assertFalse(manager.connect_standby_node(standby_id))

        logged = " ".join(str(call.args) for call in log_mock.call_args_list)
        self.assertIn("主隧道已消失", logged)

class ProxyServerConcurrencyTests(unittest.TestCase):
    def test_socks5_rejects_client_without_no_auth_method(self) -> None:
        class Client:
            def __init__(self):
                self.incoming = bytearray(b"\x01\x02")
                self.sent = bytearray()
                self.closed = False

            def recv(self, size):
                chunk = self.incoming[:size]
                del self.incoming[:size]
                return bytes(chunk)

            def sendall(self, data):
                self.sent.extend(data)

            def close(self):
                self.closed = True

        client = Client()
        with mock.patch.object(proxy_server, "proxy_auth_enabled", return_value=False):
            proxy_server.socks5_client(client, b"\x05")

        self.assertEqual(b"\x05\xff", bytes(client.sent))
        self.assertTrue(client.closed)

    def test_each_proxy_worker_keeps_its_accepted_socket(self) -> None:
        class Client:
            def __init__(self, name):
                self.name = name

            def close(self):
                pass

        class FakeServer:
            def __init__(self):
                self.items = [(Client("first"), ("first", 1)), (Client("second"), ("second", 2))]

            def setsockopt(self, *args):
                pass

            def bind(self, *args):
                pass

            def listen(self, *args):
                pass

            def accept(self):
                if self.items:
                    return self.items.pop(0)
                raise KeyboardInterrupt()

        class DeferredThread:
            targets = []

            def __init__(self, target, daemon=True):
                self.target = target
                self.targets.append(target)

            def start(self):
                pass

        seen = []
        semaphore = mock.Mock()
        semaphore.acquire.return_value = True
        with (
            mock.patch.object(proxy_server.socket, "socket", return_value=FakeServer()),
            mock.patch.object(proxy_server.threading, "Thread", DeferredThread),
            mock.patch.object(
                proxy_server,
                "proxy_client",
                side_effect=lambda client, address: seen.append((client.name, address[0])),
            ),
            mock.patch.object(proxy_server, "proxy_connection_sem", semaphore),
        ):
            with self.assertRaises(KeyboardInterrupt):
                proxy_server.start_proxy_server("127.0.0.1", 7928)
            for target in DeferredThread.targets:
                target()

        self.assertEqual([("first", "first"), ("second", "second")], seen)


    def test_merge_keeps_live_standby_node_absent_from_snapshot(self) -> None:
        """A live standby node must survive the periodic refresh merge even
        when the fresh snapshot no longer contains it (regression: the UI
        standby badge used to vanish every refresh cycle)."""
        old_proc, old_id, old_active = (
            manager.standby_openvpn_process,
            manager.standby_openvpn_node_id,
            manager.active_openvpn_node_id,
        )
        proc = FakeProcess()
        manager.standby_openvpn_process = proc
        manager.standby_openvpn_node_id = "node-standby"
        manager.active_openvpn_node_id = "node-active"
        try:
            current = [
                {"id": "node-active", "active": True},
                {"id": "node-standby", "standby": True, "probe_status": "available"},
                {"id": "node-gone", "probe_status": "available"},
            ]
            # fresh snapshot: active node present, standby node missing
            candidates = [
                {"id": "node-active", "config_file": "/tmp/x", "ping": 10},
                {"id": "node-new", "config_file": "/tmp/y", "ping": 20},
            ]
            with manager.lock:
                merged = manager.merge_fresh_candidates(current, candidates)
            by_id = {n["id"]: n for n in merged}
            self.assertIn("node-standby", by_id)
            self.assertTrue(by_id["node-standby"]["standby"])
            self.assertTrue(by_id["node-active"].get("active"))
            self.assertNotIn("node-gone", by_id)
            self.assertIn("node-new", by_id)
            # exactly one standby marker in the whole list
            self.assertEqual(
                1, sum(1 for n in merged if n.get("standby"))
            )
        finally:
            manager.standby_openvpn_process = old_proc
            manager.standby_openvpn_node_id = old_id
            manager.active_openvpn_node_id = old_active

    def test_merge_clears_standby_marker_when_no_live_standby(self) -> None:
        old_proc, old_id = (
            manager.standby_openvpn_process,
            manager.standby_openvpn_node_id,
        )
        manager.standby_openvpn_process = None
        manager.standby_openvpn_node_id = ""
        try:
            current = [{"id": "node-a", "standby": True}]
            candidates = [{"id": "node-a", "config_file": "/tmp/x"}]
            with manager.lock:
                merged = manager.merge_fresh_candidates(current, candidates)
            self.assertFalse(any(n.get("standby") for n in merged))
        finally:
            manager.standby_openvpn_process = old_proc
            manager.standby_openvpn_node_id = old_id

    def test_standby_healthy_requires_kernel_device(self) -> None:
        """A live process without its tun device must not count as healthy,
        otherwise the monitor never rebuilds a broken standby tunnel."""
        old_proc, old_id, old_dev = (
            manager.standby_openvpn_process,
            manager.standby_openvpn_node_id,
            manager.standby_tun_dev,
        )
        manager.standby_openvpn_process = FakeProcess()
        manager.standby_openvpn_node_id = "node-standby"
        # point at a device that cannot exist on the test machine
        manager.standby_tun_dev = "tun9"
        try:
            import sys as _sys

            if _sys.platform.startswith("linux"):
                self.assertFalse(manager.standby_healthy())
            else:
                self.assertTrue(manager.standby_healthy())
        finally:
            manager.standby_openvpn_process = old_proc
            manager.standby_openvpn_node_id = old_id
            manager.standby_tun_dev = old_dev


    def test_verify_standby_egress_tears_down_dead_tunnel(self) -> None:
        """出口不通的热备隧道应被拆除重建，而不是留着等切换时空切。"""
        old_dev, old_id = manager.standby_tun_dev, manager.standby_openvpn_node_id
        manager.standby_tun_dev = "tun1"
        manager.standby_openvpn_node_id = "node-dead"
        try:
            with mock.patch.object(manager, "check_tunnel_health", return_value=False), \
                 mock.patch.object(manager, "stop_standby_openvpn") as stop_mock:
                manager._verify_standby_egress("tun1", "node-dead")
            stop_mock.assert_called_once()
        finally:
            manager.standby_tun_dev = old_dev
            manager.standby_openvpn_node_id = old_id

    def test_verify_standby_egress_keeps_healthy_tunnel(self) -> None:
        """出口正常的热备隧道不应被动。"""
        old_dev, old_id = manager.standby_tun_dev, manager.standby_openvpn_node_id
        manager.standby_tun_dev = "tun1"
        manager.standby_openvpn_node_id = "node-ok"
        try:
            with mock.patch.object(manager, "check_tunnel_health", return_value=True), \
                 mock.patch.object(manager, "stop_standby_openvpn") as stop_mock:
                manager._verify_standby_egress("tun1", "node-ok")
            stop_mock.assert_not_called()
        finally:
            manager.standby_tun_dev = old_dev
            manager.standby_openvpn_node_id = old_id

    def test_verify_standby_egress_aborts_after_failover(self) -> None:
        """巡检期间若发生故障切换（热备已转正），不得拆除新的热备。"""
        old_dev, old_id = manager.standby_tun_dev, manager.standby_openvpn_node_id
        # 模拟巡检开始后发生了切换：standby 全局变量已变更
        manager.standby_tun_dev = "tun0"
        manager.standby_openvpn_node_id = ""
        try:
            with mock.patch.object(manager, "check_tunnel_health", return_value=False), \
                 mock.patch.object(manager, "stop_standby_openvpn") as stop_mock:
                manager._verify_standby_egress("tun1", "node-old")
            stop_mock.assert_not_called()
        finally:
            manager.standby_tun_dev = old_dev
            manager.standby_openvpn_node_id = old_id


    def test_hot_standby_allowed_respects_ui_toggle(self) -> None:
        with mock.patch.object(
            manager, "load_ui_config", return_value={"hot_standby_enabled": False}
        ):
            self.assertFalse(manager.hot_standby_allowed())
        with mock.patch.object(
            manager, "load_ui_config", return_value={"hot_standby_enabled": True}
        ):
            self.assertTrue(manager.hot_standby_allowed())
        # missing key defaults to enabled
        with mock.patch.object(manager, "load_ui_config", return_value={}):
            self.assertTrue(manager.hot_standby_allowed())
        # env hard-gate wins over the UI toggle
        with (
            mock.patch.object(
                manager, "load_ui_config", return_value={"hot_standby_enabled": True}
            ),
            mock.patch.object(manager, "HOT_STANDBY_ENABLED", False),
        ):
            self.assertFalse(manager.hot_standby_allowed())

if __name__ == "__main__":
    unittest.main()
