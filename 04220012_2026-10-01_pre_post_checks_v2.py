#!/usr/bin/env python3
"""
panos_upgrade_assurance.py
===========================

Pre-upgrade / Post-upgrade validation and state-comparison tool for
Palo Alto Networks firewalls, built on top of:

    - pan-os-python                (PanDevice / Firewall connection objects)
    - panos-upgrade-assurance      (FirewallProxy, CheckFirewall, SnapshotCompare)

Workflow
--------
At startup the script prompts for a change record number (e.g. CHG0012345).
That value is used as the leading component of every output filename so that
all artifacts are clearly tied to a specific change ticket.

For every device in the inventory:

    1. Connect to the firewall (PAN-OS API, getpass-collected credentials).
    2. Derive the file prefix:  <change_record>_<hostname>
    3. Look for "<change_record>_<hostname>_pre_check.json" in the local directory.
         - If it does NOT exist:
               * This is a PRE-UPGRADE run.
               * Run readiness checks + state snapshot.
               * Save raw output to "<change_record>_<hostname>_pre_check.json".
         - If it DOES exist:
               * This is a POST-UPGRADE run.
               * Run the same readiness checks + state snapshot.
               * Save raw output to "<change_record>_<hostname>_post_check.json".
               * Compare pre vs. post using panos-upgrade-assurance's
                 SnapshotCompare (plus a manual diff for the custom,
                 non-native data points collected via op commands).
               * Save the diff to "<change_record>_<hostname>_comparison.json".
               * Print a human-readable summary to the console.

Inventory
---------
Devices can be supplied in any of the following ways (first match wins):

    1. `--host` CLI argument            -> single device
    2. `--inventory-file` CLI argument  -> path to a CSV file
    3. `devices.csv` in the local dir   -> auto-discovered CSV
    4. STATIC_INVENTORY (in this file)  -> hard-coded fallback list

CSV format (header optional, one column or named column "host"):

    host
    fw1.example.com
    10.0.0.1
    fw2.example.com

Install dependencies
---------------------
    pip install pan-os-python panos-upgrade-assurance

Usage
-----
    python panos_upgrade_assurance.py                              # use CSV/static inventory
    python panos_upgrade_assurance.py --host 10.0.0.1              # single device
    python panos_upgrade_assurance.py --inventory-file my_devices.csv
    python panos_upgrade_assurance.py --change-record CHG0012345   # skip interactive prompt
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import logging
import os
import sys
import traceback
from dataclasses import dataclass, field
import datetime as dt
from typing import Any, Dict, List, Optional, Union

# --------------------------------------------------------------------------- #
# Third-party imports (pan-os-python / panos-upgrade-assurance)
# --------------------------------------------------------------------------- #
try:
    from panos.firewall import Firewall
    from panos.errors import (
        PanXapiError,
        PanConnectionTimeout,
        PanURLError,
    )
except ImportError as exc:  # pragma: no cover
    print(
        "ERROR: 'pan-os-python' is required. Install it with: "
        "pip install pan-os-python",
        file=sys.stderr,
    )
    raise

try:
    from panos_upgrade_assurance.firewall_proxy import FirewallProxy
    from panos_upgrade_assurance.check_firewall import CheckFirewall
    from panos_upgrade_assurance.snapshot_compare import SnapshotCompare
except ImportError:  # pragma: no cover
    print(
        "ERROR: 'panos-upgrade-assurance' is required. Install it with: "
        "pip install panos-upgrade-assurance",
        file=sys.stderr,
    )
    raise


# --------------------------------------------------------------------------- #
# Logging configuration
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("panos_upgrade_assurance")


# --------------------------------------------------------------------------- #
# Static fallback inventory - edit directly if you don't want to use a CSV
# --------------------------------------------------------------------------- #
STATIC_INVENTORY: List[str] = [
     "192.168.4.16",
    # "fw2.example.com",
    # "10.0.0.1",
]

DEFAULT_CSV_NAME = "devices.csv"


# --------------------------------------------------------------------------- #
# Readiness-check configuration
#
# These keys map to the native `panos-upgrade-assurance` readiness checks
# (CheckFirewall.run_readiness_checks). Native readiness checks cover HA
# state/sync, disk space, and a handful of plane-health items. State items
# that are not exposed as "readiness checks" (routing table, ARP table,
# session count, BGP/OSPF peers, BGP RIB, IPSec tunnels, interface status,
# MP/DP CPU) are pulled either via the native snapshot state mechanism
# (`CheckFirewall.run_snapshots`) or via direct PAN-OS "op" commands wrapped
# in CUSTOM_OP_CHECKS below.
# --------------------------------------------------------------------------- #

# 1) Native readiness checks (boolean pass/fail style validations)
READINESS_CHECKS_CONFIG: List[Any] = [
    {"ha": {}},                 # HA state / configuration sanity
    {"free_disk_space": {}},    # Disk space check
    #{"session_exist": {}},      # Sanity check that the session table is alive
    #{"ip_sec_tunnel_status": {}},  # IPSec tunnel status (readiness flavor)
    #{"arp_entry_exist": {}},    # Sanity check on ARP table presence
    {"mp_cpu_utilization": {}},    # Check Management plane CPU Usage
    {"dp_cpu_utilization": {}},    # Check Dataplane CPU Usage
    {"candidate_config": {}},    # Verifies if there are any changes on the device pending to be committed
    {"panorama": {}},    # Verifies panorama connectivity
]

# 2) Native state-snapshot areas (raw data captured for diffing)
#
#    NOTE: This list is passed to CheckFirewall.run_snapshots(). A dict entry's
#    value is expanded as **kwargs into the snapshot *capture* method, so do
#    NOT put comparison options (properties / count_change_threshold /
#    thresholds) here - those belong in SNAPSHOT_REPORT_CONFIG /
#    SNAPSHOT_IGNORE_KEYS below.
SNAPSHOT_STATE_AREAS: List[Union[str, Dict[str, Any]]] = [
    "nics",            # Interface status
    "routes",          # Routing table
    "arp_table",       # ARP table
    "session_stats",   # Active session count / stats
    "ip_sec_tunnels",  # IPSec tunnel status (state flavor)
    "license",         # Useful context for upgrade-related licensing drift
    "content_version", # Grabs the currently installed Content DB version.
    "bgp_peers",       # Takes a snapshot of configuration of BGP peers along with their status.
    "fib_routes",      # Takes a snapshot of the Forwarding table
    {"mtu": {"include_subinterfaces": True}},             # Takes a snapshot of MTU sizes for all interfaces on the device.
    "are_routes",      # Advanced Routing Engine route table
    "are_fib_routes",  # Advanced Routing Engine forwarding table
]

# 2a) Per-area comparison (report) options passed to
#     SnapshotCompare.compare_snapshots(). Supported keys per area:
#
#       generic areas (nics, routes, arp_table, bgp_peers, fib_routes, mtu,
#       license, content_version, ip_sec_tunnels):
#           "properties": ["!key", ...]  -> keys to skip at ANY nesting level
#                                          (ConfigParser dialect; "!" = exclude)
#           "count_change_threshold": N  -> max % of entries allowed to change
#
#       session_stats (metric comparison - properties NOT supported):
#           "thresholds": [{"num-active": 10}, ...]  -> % change allowed per key
#           (without thresholds session_stats comparison returns None)
#
#     Avoid mixing positive and "!" entries in "properties": if any positive
#     entry exists, ONLY the positively-listed keys are compared.
SNAPSHOT_REPORT_CONFIG: Dict[str, Dict[str, Any]] = {
     "routes": {"count_change_threshold": 5},
     "session_stats": {"thresholds": [{"num-active": 10}, {"num-tcp": 10}, {"cps": 10}]},
     "arp_table": {"count_change_threshold": 10},
     "are_routes": {"count_change_threshold": 5},
}

# 2b) Convenience ignore list: area -> keys to ignore in the comparison.
#     Each key is converted to a "!key" exclusion and merged into
#     SNAPSHOT_REPORT_CONFIG[area]["properties"]. Keys match at ANY level of the
#     snapshot (an entry name such as a route key, or a field inside entries).
#     For session_stats, listed keys are removed from "thresholds" instead.
SNAPSHOT_IGNORE_KEYS: Dict[str, List[str]] = {
    "routes": ["age"],          
    "fib_routes": ["age"],
    "are_routes": ["uptime"],   
    "are_fib_routes": ["age"],
    "arp_table": ["ttl", "port"],        
    "nics": [],
    "ip_sec_tunnels": [],
    "bgp_peers": ["status-duration", "last-error"],
    "license": ["expires", "expired"],
    "content_version": [],               
}

# 2c) Keys to ignore in the manual (shallow) diffs of readiness checks and
#     custom op-command output.
READINESS_IGNORE_KEYS: List[str] = [
    # "candidate_config",
]
CUSTOM_CHECK_IGNORE_KEYS: List[str] = [
    # "mp_cpu_usage",
]

# 3) Custom op-command based checks for items not natively modeled by the
#    panos-upgrade-assurance snapshot/readiness mechanisms (BGP peers, BGP
#    RIB per peer, OSPF peers, MP/DP CPU usage, HA sync detail).
CUSTOM_OP_CHECKS: Dict[str, str] = {
    #"ha_sync_status": "show high-availability state",
    #"bgp_peers_status": "show routing protocol bgp peer",
    #"bgp_rib": "show routing protocol bgp loc-rib",
    #"ospf_peers_status": "show routing protocol ospf neighbor",
    #"mp_cpu_usage": "show system resources",
    #"dp_cpu_usage": "show running resource-monitor",
}


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
@dataclass
class DeviceCredentials:
    username: str
    password: str
    api_key: Optional[str] = None


@dataclass
class DeviceResult:
    host: str
    change_record: str = ""
    phase: str = "unknown"          # "pre" | "post" | "failed"
    success: bool = False
    error: Optional[str] = None
    pre_file: Optional[str] = None
    post_file: Optional[str] = None
    comparison_file: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Inventory handling
# --------------------------------------------------------------------------- #
def load_inventory_from_csv(path: str) -> List[str]:
    """Read a list of hosts/IPs from a CSV file.

    Supports either a single unlabeled column, or a column explicitly
    named 'host' / 'hostname' / 'ip'.
    """
    hosts: List[str] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(2048)
        fh.seek(0)
        has_header = csv.Sniffer().has_header(sample) if sample.strip() else False
        reader = csv.reader(fh)
        rows = list(reader)

    if not rows:
        return hosts

    start_idx = 0
    col_idx = 0
    if has_header:
        header = [c.strip().lower() for c in rows[0]]
        for candidate in ("host", "hostname", "ip", "device", "address"):
            if candidate in header:
                col_idx = header.index(candidate)
                break
        start_idx = 1

    for row in rows[start_idx:]:
        if not row:
            continue
        value = row[col_idx].strip()
        if value:
            hosts.append(value)

    return hosts


def resolve_inventory(args: argparse.Namespace) -> List[str]:
    """Determine the device inventory based on CLI args / CSV / static list."""
    if args.host:
        logger.info("Using single device supplied via --host: %s", args.host)
        return [args.host]

    csv_path = args.inventory_file or (
        DEFAULT_CSV_NAME if os.path.isfile(DEFAULT_CSV_NAME) else None
    )

    if csv_path:
        if not os.path.isfile(csv_path):
            logger.error("Inventory CSV file not found: %s", csv_path)
            sys.exit(1)
        hosts = load_inventory_from_csv(csv_path)
        if hosts:
            logger.info("Loaded %d device(s) from CSV: %s", len(hosts), csv_path)
            return hosts
        logger.warning("CSV file %s contained no usable host entries.", csv_path)

    if STATIC_INVENTORY:
        logger.info(
            "Using static in-script inventory (%d device(s)).", len(STATIC_INVENTORY)
        )
        return list(STATIC_INVENTORY)

    logger.error(
        "No inventory found. Provide --host, --inventory-file, a local "
        "'%s', or populate STATIC_INVENTORY in the script.",
        DEFAULT_CSV_NAME,
    )
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Credential handling
# --------------------------------------------------------------------------- #
def collect_credentials() -> DeviceCredentials:
    """Securely prompt for API credentials using getpass."""
    logger.info("Collecting firewall credentials (input is hidden where applicable).")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    if not username or not password:
        logger.error("Username and password are required.")
        sys.exit(1)
    return DeviceCredentials(username=username, password=password)


# --------------------------------------------------------------------------- #
# Change record handling
# --------------------------------------------------------------------------- #
def collect_change_record(cli_value: Optional[str] = None) -> str:
    """Return the change record number, prompting interactively if not supplied.

    The value is stripped of surrounding whitespace and must be non-empty.
    Characters that are invalid in filenames ( / \\ : * ? " < > | ) are
    rejected to prevent accidental path injection in output filenames.
    """
    _INVALID_CHARS = set('/\\:*?"<>|')

    def _validate(value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Change record number cannot be empty.")
        bad = [c for c in value if c in _INVALID_CHARS]
        if bad:
            raise ValueError(
                f"Change record contains invalid filename character(s): "
                f"{' '.join(repr(c) for c in bad)}"
            )
        return value

    if cli_value is not None:
        try:
            validated = _validate(cli_value)
            logger.info("Change record number (from CLI): %s", validated)
            return validated
        except ValueError as exc:
            logger.error("Invalid --change-record value: %s", exc)
            sys.exit(1)

    while True:
        try:
            raw = input("Change record number (e.g. CHG0012345): ").strip()
            validated = _validate(raw)
            logger.info("Change record number accepted: %s", validated)
            return validated
        except ValueError as exc:
            logger.warning("%s  Please try again.", exc)


# --------------------------------------------------------------------------- #
# Connection handling
# --------------------------------------------------------------------------- #
def connect_firewall(host: str, creds: DeviceCredentials) -> Firewall:
    """Establish an authenticated connection to a single firewall."""
    logger.info("Connecting to %s ...", host)
    try:
        fw = Firewall(host, creds.username, creds.password)
        # Force a lightweight API call to validate connectivity/auth early.
        fw.refresh_system_info()
        logger.info("Connected to %s (hostname reported: %s)", host, fw.hostname)
        return fw
    except PanConnectionTimeout as exc:
        raise ConnectionError(f"Connection to {host} timed out: {exc}") from exc
    except PanURLError as exc:
        raise ConnectionError(f"Unable to reach {host}: {exc}") from exc
    except PanXapiError as exc:
        raise PermissionError(f"Authentication/API error for {host}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - surface any unexpected error
        raise RuntimeError(f"Unexpected error connecting to {host}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Data collection
# --------------------------------------------------------------------------- #
def run_custom_op_checks(fw: Firewall) -> Dict[str, Any]:
    """Execute the supplementary op-command checks not natively covered by
    panos-upgrade-assurance (BGP/OSPF peers, BGP RIB, MP/DP CPU, HA sync).
    Each failure is captured individually so one bad command does not abort
    the whole snapshot.
    """
    results: Dict[str, Any] = {}
    for key, cmd in CUSTOM_OP_CHECKS.items():
        try:
            xml_resp = fw.op(cmd, xml=True)
            results[key] = xml_resp.decode("utf-8") if isinstance(xml_resp, bytes) else str(xml_resp)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Custom op-check '%s' (%s) failed: %s", key, cmd, exc)
            results[key] = {"error": str(exc)}
    return results


def run_readiness_checks_isolated(
    check_executor: CheckFirewall,
    hostname: str,
) -> Dict[str, Any]:
    """Run each readiness check individually so one failing check does not
    abort the rest.

    ``CheckFirewall.run_readiness_checks`` loops over all checks with no
    per-check exception handling, so a single exception (e.g. the panorama
    check on a cloud-managed firewall raising MalformedResponseException)
    discards every other result. Here each check is invoked on its own and
    any exception is recorded in the same shape as a native CheckResult
    (``state`` / ``status`` / ``reason``) so downstream diffing is unchanged.
    """
    results: Dict[str, Any] = {}

    for entry in READINESS_CHECKS_CONFIG:
        if isinstance(entry, dict):
            if len(entry) != 1:
                logger.warning("[%s] Ignoring malformed readiness check entry: %r", hostname, entry)
                continue
            check_name = next(iter(entry))
        elif isinstance(entry, str):
            check_name = entry
        else:
            logger.warning("[%s] Ignoring malformed readiness check entry: %r", hostname, entry)
            continue

        try:
            results.update(
                check_executor.run_readiness_checks(
                    checks_configuration=[entry],
                    report_style=False,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "[%s] Readiness check '%s' raised an exception: %s",
                hostname,
                check_name,
                exc,
            )
            results[check_name] = {
                "state": False,
                "status": "ERROR",
                "reason": f"{type(exc).__name__}: {exc}",
            }

    return results


def collect_state(fw: Firewall, proxy: FirewallProxy, check_executor: CheckFirewall) -> Dict[str, Any]:
    """Run readiness checks + native snapshots + custom op checks and
    assemble a single combined state dictionary."""

    state: Dict[str, Any] = {
        "metadata": {
            "hostname": fw.hostname,
            "ip_address": getattr(fw, "hostname", None),
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat() + "Z",
        }
    }

    # --- Native readiness checks (HA state/sync sanity, disk space, etc.) ---
    # Each check runs in isolation; a failure in one (e.g. panorama on a
    # cloud-managed device) is recorded as an ERROR for that check only.
    logger.info("[%s] Running readiness checks...", fw.hostname)
    state["readiness_checks"] = run_readiness_checks_isolated(check_executor, fw.hostname)

    # --- Native state snapshots (routing table, ARP table, sessions, etc.) -
    try:
        logger.info("[%s] Capturing state snapshot...", fw.hostname)
        snapshot_results = check_executor.run_snapshots(
            snapshots_config=SNAPSHOT_STATE_AREAS
        )
        state["state_snapshot"] = snapshot_results
    except Exception as exc:  # noqa: BLE001
        logger.error("[%s] State snapshot failed: %s", fw.hostname, exc)
        state["state_snapshot"] = {"error": str(exc)}

    # --- Custom op-command checks (BGP/OSPF peers, BGP RIB, CPU, HA sync) --
    logger.info("[%s] Running custom op-command checks (BGP/OSPF/CPU/HA sync)...", fw.hostname)
    state["custom_checks"] = run_custom_op_checks(fw)

    return state


# --------------------------------------------------------------------------- #
# Persistence helpers
# --------------------------------------------------------------------------- #
def save_json(data: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=4, default=str)
    logger.info("Saved: %s", path)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Comparison logic
# --------------------------------------------------------------------------- #
def build_report_config(area: str) -> Dict[str, Any]:
    """Merge SNAPSHOT_REPORT_CONFIG and SNAPSHOT_IGNORE_KEYS for one area into
    the report configuration accepted by ``SnapshotCompare``.

    Returns a fresh dict each call (SnapshotCompare mutates report configs).
    """
    config: Dict[str, Any] = {
        k: (list(v) if isinstance(v, list) else v)
        for k, v in SNAPSHOT_REPORT_CONFIG.get(area, {}).items()
    }
    ignore_keys = [k for k in SNAPSHOT_IGNORE_KEYS.get(area, []) if k]
    if not ignore_keys:
        return config

    if area == "session_stats":
        # Metric comparison does not support "properties"; drop ignored keys
        # from the thresholds list instead.
        if "thresholds" in config:
            config["thresholds"] = [
                t for t in config["thresholds"] if next(iter(t)) not in ignore_keys
            ]
        return config

    properties: List[str] = config.get("properties", [])
    if any(not p.startswith("!") for p in properties):
        logger.warning(
            "[%s] 'properties' contains positive entries; only those keys are "
            "compared, so ignore keys %s have limited effect.",
            area,
            ignore_keys,
        )
    for key in ignore_keys:
        excl = key if key.startswith("!") else f"!{key}"
        if excl not in properties:
            properties.append(excl)
    config["properties"] = properties
    return config


def build_snapshot_reports(
    pre_snapshot: Dict[str, Any],
    post_snapshot: Dict[str, Any],
) -> List[Union[Dict[str, Any], str]]:
    """Build the ``reports`` argument for ``SnapshotCompare.compare_snapshots``.

    Only areas present in BOTH snapshots are included, preserving the order
    defined in ``SNAPSHOT_STATE_AREAS``. Areas missing from either side are
    logged so a partially-failed capture doesn't silently shrink the diff.
    Per-area comparison options and ignore keys come from
    ``SNAPSHOT_REPORT_CONFIG`` / ``SNAPSHOT_IGNORE_KEYS`` (never from the
    capture config in ``SNAPSHOT_STATE_AREAS``).
    """
    reports: List[Union[Dict[str, Any], str]] = []
    skipped: List[str] = []

    for entry in SNAPSHOT_STATE_AREAS:
        # Entries may be a bare area name ("routes") or a single-key capture
        # config dict ({"routes": {...}}). Only the name is relevant here.
        if isinstance(entry, dict):
            if len(entry) != 1:
                logger.warning("Ignoring malformed snapshot area entry: %r", entry)
                continue
            area = next(iter(entry))
        else:
            area = entry

        if area not in pre_snapshot or area not in post_snapshot:
            skipped.append(f"{area} (missing)")
            continue

        # run_snapshots() always emits every requested area, but a failed
        # capture (e.g. legacy routing commands under Advanced Routing Mode)
        # yields {"state": False, "snapshot": None, ...}. SnapshotCompare
        # raises SnapshotNoneComparisonException for such areas and aborts the
        # whole comparison, so exclude them up front.
        pre_area = pre_snapshot.get(area)
        post_area = post_snapshot.get(area)
        pre_data = pre_area.get("snapshot") if isinstance(pre_area, dict) else None
        post_data = post_area.get("snapshot") if isinstance(post_area, dict) else None
        if pre_data is None or post_data is None:
            reasons = []
            if pre_data is None:
                reasons.append(f"pre: {(pre_area or {}).get('reason') or 'no data'}")
            if post_data is None:
                reasons.append(f"post: {(post_area or {}).get('reason') or 'no data'}")
            skipped.append(f"{area} ({'; '.join(reasons)})")
            continue

        reports.append({area: build_report_config(area)})

    if skipped:
        logger.warning(
            "Skipping snapshot areas without usable data on both sides: %s",
            ", ".join(skipped),
        )

    return reports


def compare_states(pre_state: Dict[str, Any], post_state: Dict[str, Any]) -> Dict[str, Any]:
    """Compare pre- and post-upgrade state using panos-upgrade-assurance's
    SnapshotCompare for the natively-supported snapshot areas, and a manual
    diff for readiness checks and custom op-command output."""

    comparison: Dict[str, Any] = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat() + "Z",
        # Record what was excluded so the report is auditable.
        "ignored_keys": {
            "snapshot": {a: k for a, k in SNAPSHOT_IGNORE_KEYS.items() if k},
            "readiness_checks": list(READINESS_IGNORE_KEYS),
            "custom_checks": list(CUSTOM_CHECK_IGNORE_KEYS),
        },
        "native_snapshot_comparison": {},
        "readiness_check_comparison": {},
        "custom_check_comparison": {},
    }

    # --- Native snapshot comparison (routes, arp_table, sessions, nics...) -
    pre_snapshot = pre_state.get("state_snapshot", {})
    post_snapshot = post_state.get("state_snapshot", {})

    snapshots_usable = (
        isinstance(pre_snapshot, dict)
        and isinstance(post_snapshot, dict)
        and bool(pre_snapshot)
        and bool(post_snapshot)
        # collect_state() stores {"error": "..."} when run_snapshots() fails.
        and "error" not in pre_snapshot
        and "error" not in post_snapshot
    )

    if not snapshots_usable:
        comparison["native_snapshot_comparison"] = {
            "note": "Insufficient data on one or both sides to run SnapshotCompare."
        }
    else:
        reports = build_snapshot_reports(pre_snapshot, post_snapshot)
        if not reports:
            # An empty list would be treated by panos-upgrade-assurance as
            # "compare everything", which then fails on the missing areas.
            comparison["native_snapshot_comparison"] = {
                "note": "No snapshot areas common to pre and post; SnapshotCompare skipped."
            }
        else:
            try:
                snap_compare = SnapshotCompare(
                    left_snapshot=pre_snapshot,
                    right_snapshot=post_snapshot,
                )
                comparison["native_snapshot_comparison"] = snap_compare.compare_snapshots(
                    reports=reports
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("SnapshotCompare failed: %s", exc)
                comparison["native_snapshot_comparison"] = {"error": str(exc)}

    # --- Readiness-check diff (pass/fail flips) ----------------------------
    comparison["readiness_check_comparison"] = diff_dict(
        pre_state.get("readiness_checks", {}),
        post_state.get("readiness_checks", {}),
        ignore_keys=READINESS_IGNORE_KEYS,
    )

    # --- Custom op-check diff (BGP/OSPF peers, CPU, HA sync) ----------------
    comparison["custom_check_comparison"] = diff_dict(
        pre_state.get("custom_checks", {}),
        post_state.get("custom_checks", {}),
        ignore_keys=CUSTOM_CHECK_IGNORE_KEYS,
    )

    return comparison


def diff_dict(
    pre: Dict[str, Any],
    post: Dict[str, Any],
    ignore_keys: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generic shallow diff between two dictionaries of comparable structure.
    Reports keys that changed, were added, or were removed. Top-level keys in
    ``ignore_keys`` are skipped and listed under ``ignored``."""
    diff: Dict[str, Any] = {"changed": {}, "added": {}, "removed": {}, "ignored": []}

    ignore = set(ignore_keys or [])
    pre = {k: v for k, v in (pre or {}).items() if k not in ignore}
    post = {k: v for k, v in (post or {}).items() if k not in ignore}
    diff["ignored"] = sorted(ignore)

    for key in post:
        if key not in pre:
            diff["added"][key] = post[key]
        elif pre[key] != post[key]:
            diff["changed"][key] = {"pre": pre[key], "post": post[key]}

    for key in pre:
        if key not in post:
            diff["removed"][key] = pre[key]

    return diff


def summarize_comparison(comparison: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a short human-readable summary dict for console logging."""
    summary = {}

    native = comparison.get("native_snapshot_comparison", {})
    if isinstance(native, dict) and "error" not in native and "note" not in native:
        passed = []
        failed = []
        for area, result in native.items():
            try:
                if isinstance(result, dict) and result.get("passed") is False:
                    failed.append(area)
                else:
                    passed.append(area)
            except Exception:
                passed.append(area)
        summary["snapshot_areas_passed"] = passed
        summary["snapshot_areas_with_changes"] = failed
    else:
        summary["snapshot_comparison_status"] = native

    ignored = comparison.get("ignored_keys", {})
    if ignored.get("snapshot"):
        summary["snapshot_ignored_keys"] = ignored["snapshot"]

    readiness_diff = comparison.get("readiness_check_comparison", {})
    summary["readiness_changed_keys"] = list(readiness_diff.get("changed", {}).keys())

    custom_diff = comparison.get("custom_check_comparison", {})
    summary["custom_changed_keys"] = list(custom_diff.get("changed", {}).keys())

    return summary


# --------------------------------------------------------------------------- #
# Per-device orchestration
# --------------------------------------------------------------------------- #
def process_device(host: str, creds: DeviceCredentials, change_record: str) -> DeviceResult:
    """Connect to *host*, run pre- or post-upgrade checks, and persist results.

    Output filenames follow the pattern:
        <change_record>_<hostname>_pre_check.json
        <change_record>_<hostname>_post_check.json
        <change_record>_<hostname>_comparison.json

    The presence of the pre-check file determines which phase is executed.
    """
    result = DeviceResult(host=host, change_record=change_record)
    try:
        fw = connect_firewall(host, creds)
        hostname = fw.hostname or host

        # Build the shared file prefix from the change record + device hostname.
        # e.g. "CHG0012345_fw1-dallas"
        file_prefix = f"{change_record}_{hostname}"
        pre_path = f"{file_prefix}_pre_check.json"

        # Log which change record / prefix is in use for full traceability.
        logger.info(
            "[%s] Change record: %s | File prefix: '%s'",
            hostname,
            change_record,
            file_prefix,
        )

        proxy = FirewallProxy(firewall=fw)
        check_executor = CheckFirewall(node=proxy)

        if not os.path.isfile(pre_path):
            # --------------------------- PRE-UPGRADE PHASE -----------------
            logger.info(
                "[%s] No pre-check file found ('%s'). Initiating PRE-UPGRADE checks...",
                hostname,
                pre_path,
            )
            result.phase = "pre"
            pre_state = collect_state(fw, proxy, check_executor)
            save_json(pre_state, pre_path)
            result.pre_file = pre_path
            result.success = True
            logger.info(
                "[%s] Pre-check snapshot successfully captured and saved to '%s'.",
                hostname,
                pre_path,
            )
        else:
            # --------------------------- POST-UPGRADE PHASE ----------------
            logger.info(
                "[%s] Pre-check file found ('%s'). Initiating POST-UPGRADE checks and comparison...",
                hostname,
                pre_path,
            )
            result.phase = "post"
            post_state = collect_state(fw, proxy, check_executor)
            post_path = f"{file_prefix}_post_check.json"
            save_json(post_state, post_path)
            result.post_file = post_path

            pre_state = load_json(pre_path)
            comparison = compare_states(pre_state, post_state)
            comparison_path = f"{file_prefix}_comparison.json"
            save_json(comparison, comparison_path)
            result.comparison_file = comparison_path

            summary = summarize_comparison(comparison)
            result.summary = summary
            result.success = True

            logger.info("[%s] ==== Comparison Summary (%s) ====", hostname, change_record)
            for k, v in summary.items():
                logger.info("[%s]   %s: %s", hostname, k, v)
            logger.info(
                "[%s] Full comparison detail saved to '%s'.", hostname, comparison_path
            )

    except (ConnectionError, PermissionError, RuntimeError) as exc:
        result.phase = "failed"
        result.success = False
        result.error = str(exc)
        logger.error("[%s] Processing failed: %s", host, exc)
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        result.phase = "failed"
        result.success = False
        result.error = f"Unexpected error: {exc}"
        logger.error("[%s] Unexpected error: %s\n%s", host, exc, traceback.format_exc())

    return result


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
def generate_change_report(change_record: str, theme: str = "auto", directory: str = ".") -> Optional[str]:
    """Build <change_record>_report.html from every device's JSON files for
    this change record. Never raises - a reporting problem must not mask the
    upgrade check results or change the script's exit code."""
    try:
        import generate_html_report  # lives next to this script
    except ImportError as exc:
        logger.warning("HTML report skipped - generate_html_report.py not importable: %s", exc)
        return None

    report_path = os.path.join(directory, f"{change_record}_report.html")
    try:
        rc = generate_html_report.main(
            [change_record, "--dir", directory, "--theme", theme, "-o", report_path]
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("HTML report generation failed: %s", exc)
        return None

    if rc != 0:
        logger.warning("HTML report generated with warnings (rc=%s) - see messages above.", rc)
    logger.info("Combined HTML report for %s: %s", change_record, os.path.abspath(report_path))
    return report_path


# --------------------------------------------------------------------------- #
# CLI / main
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PAN-OS pre/post upgrade validation and comparison tool."
    )
    parser.add_argument(
        "--host",
        help="Single device hostname or IP address to process (overrides inventory file).",
    )
    parser.add_argument(
        "--inventory-file",
        help=f"Path to a CSV inventory file (default: ./{DEFAULT_CSV_NAME} if present).",
    )
    parser.add_argument(
        "--change-record",
        metavar="CR_NUMBER",
        help=(
            "Change record number used as the prefix for all output filenames "
            "(e.g. CHG0012345). If omitted the script will prompt interactively."
        ),
    )
    parser.add_argument(
        "--no-html-report",
        action="store_true",
        help="Do not build the combined HTML report after post-checks complete.",
    )
    parser.add_argument(
        "--report-theme",
        choices=("auto", "light", "dark"),
        default="auto",
        help="Default theme for the generated HTML report (default: auto).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Collect the change record number first — it drives the output filenames
    # and determines which phase (pre vs. post) is executed for each device.
    change_record = collect_change_record(cli_value=args.change_record)

    inventory = resolve_inventory(args)
    creds = collect_credentials()

    logger.info(
        "Starting run | Change record: %s | Devices (%d): %s",
        change_record,
        len(inventory),
        inventory,
    )

    results: List[DeviceResult] = []
    for host in inventory:
        results.append(process_device(host, creds, change_record))

    logger.info("==================== RUN COMPLETE ====================")
    succeeded = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    logger.info(
        "Change record: %s | Succeeded: %d | Failed: %d",
        change_record,
        len(succeeded),
        len(failed),
    )

    for r in results:
        status = "OK" if r.success else "FAILED"
        logger.info(
            " - %s [%s] phase=%s%s",
            r.host,
            status,
            r.phase,
            f" error={r.error}" if r.error else "",
        )

    # Build the combined HTML report once every device is done, but only if
    # this run actually produced at least one *_comparison.json.
    new_comparisons = [r for r in results if r.success and r.phase == "post" and r.comparison_file]
    if new_comparisons and not args.no_html_report:
        generate_change_report(change_record, theme=args.report_theme)
    elif not new_comparisons:
        logger.info("No comparison files produced this run - HTML report not generated.")

    if failed:
        sys.exit(2)


if __name__ == "__main__":
    main()