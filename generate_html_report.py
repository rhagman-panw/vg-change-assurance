#!/usr/bin/env python3
"""
generate_html_report.py

Build a self-contained HTML report from the JSON files produced by
``04220012_2026-10-01_pre_post_checks_v2.py``:

    <change_record>_<hostname>_pre_check.json
    <change_record>_<hostname>_post_check.json    (optional)
    <change_record>_<hostname>_comparison.json    (optional)

All devices that share a change record are combined into ONE report
(``<change_record>_report.html``) containing:

  * an overview table - one row per device with its overall status and the
    status of every section, linking to that device's detail block;
  * a collapsible block per device with readiness checks, snapshot capture,
    snapshot comparison and custom op checks. Every entry has a
    PASS / FAIL / ERROR / SKIPPED badge and expands to show the exact reason
    or the precise pre -> post difference.

Usage:
    python generate_html_report.py                        # one report per change record found in cwd
    python generate_html_report.py CHG1234                # all devices for CHG1234
    python generate_html_report.py CHG1234 CHG5678        # one report per listed change record
    python generate_html_report.py CHG1234_192.168.4.16   # a single device only
    python generate_html_report.py CHG1234 --dir ./out -o CHG1234.html
    python generate_html_report.py --pre a.json --post b.json --comparison c.json -o out.html

Only the Python standard library is used; the output HTML has no external
dependencies and can be emailed / attached to a change record as-is.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import html
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

PRE_SUFFIX = "_pre_check.json"
POST_SUFFIX = "_post_check.json"
COMP_SUFFIX = "_comparison.json"

# --------------------------------------------------------------------------- #
# Status model
# --------------------------------------------------------------------------- #
PASS, FAIL, ERROR, SKIP, NA, INFO = "pass", "fail", "error", "skip", "na", "info"

STATUS_LABEL = {
    PASS: "PASS",
    FAIL: "FAIL",
    ERROR: "ERROR",
    SKIP: "SKIPPED",
    NA: "N/A",
    INFO: "INFO",
}

# Higher number = worse. Used to roll multiple statuses up into one.
SEVERITY = {PASS: 0, NA: 1, INFO: 1, SKIP: 2, FAIL: 3, ERROR: 4}


def worst(statuses: Iterable[str]) -> str:
    statuses = [s for s in statuses if s]
    return max(statuses, key=lambda s: SEVERITY.get(s, 0)) if statuses else NA


def check_status(entry: Any) -> str:
    """Map a panos-upgrade-assurance CheckResult-style dict to a status."""
    if entry is None:
        return NA
    if not isinstance(entry, dict):
        return ERROR
    status = str(entry.get("status", "")).upper()
    if status == "SKIPPED":
        return SKIP
    if status == "ERROR":
        return ERROR
    if entry.get("state") is True or status == "SUCCESS":
        return PASS
    if "error" in entry and len(entry) == 1:
        return ERROR
    return FAIL


# --------------------------------------------------------------------------- #
# Small HTML helpers
# --------------------------------------------------------------------------- #
def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def fmt_value(value: Any) -> str:
    """Render a scalar or structure as escaped text."""
    if isinstance(value, (dict, list)):
        return f"<pre>{esc(json.dumps(value, indent=2, sort_keys=True))}</pre>"
    return esc(value)


def badge(status: str) -> str:
    return f'<span class="badge {status}">{STATUS_LABEL.get(status, status.upper())}</span>'


def details(
    title: str,
    status: str,
    body: str,
    *,
    open_: bool = False,
    extra: str = "",
    top_level: bool = False,
) -> str:
    cls = f"item {status}" + (" top" if top_level else "")
    return (
        f'<details class="{cls}"{" open" if open_ else ""}>'
        f'<summary>{badge(status)}<span class="name">{esc(title)}</span>'
        f'<span class="extra">{extra}</span></summary>'
        f'<div class="body">{body}</div></details>'
    )


def json_block(data: Any, label: str = "Raw data") -> str:
    return (
        f'<details class="raw"><summary>{esc(label)}</summary>'
        f"<pre>{esc(json.dumps(data, indent=2, sort_keys=True))}</pre></details>"
    )


def table(headers: List[str], rows: List[List[str]], cls: str = "", row_attrs: Optional[List[str]] = None) -> str:
    """``row_attrs`` is a list of pre-escaped attribute strings, one per row."""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = ""
    for i, r in enumerate(rows):
        ra = f" {row_attrs[i]}" if row_attrs else ""
        body += f"<tr{ra}>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
    cls_attr = f' class="{cls}"' if cls else ""
    return f"<table{cls_attr}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def muted(text: str) -> str:
    return f'<p class="muted">{esc(text)}</p>'


# --------------------------------------------------------------------------- #
# Section: readiness checks
# --------------------------------------------------------------------------- #
def normalise_checks(block: Any) -> Dict[str, Any]:
    """Readiness / snapshot blocks may be ``{"error": "..."}`` when the whole
    run aborted (older script versions). Present that as a single entry."""
    if not isinstance(block, dict):
        return {}
    if set(block) == {"error"} and isinstance(block["error"], str):
        return {"(entire run)": {"state": False, "status": "ERROR", "reason": block["error"]}}
    return block


def render_check_pair(name: str, pre: Any, post: Any, has_post: bool) -> Tuple[str, str]:
    pre_s = check_status(pre) if pre is not None else NA
    post_s = check_status(post) if post is not None else NA
    overall = post_s if has_post else pre_s
    if has_post and pre is not None and post is None:
        overall = ERROR  # check disappeared in post run

    extra = f'<span class="lbl">Pre</span>{badge(pre_s)}'
    if has_post:
        extra += f'<span class="lbl">Post</span>{badge(post_s)}'
        if pre_s != post_s and pre is not None and post is not None:
            extra += '<span class="flag">status changed</span>'

    rows = []
    for label, entry, st in (("Pre-check", pre, pre_s), ("Post-check", post, post_s)):
        if label == "Post-check" and not has_post:
            continue
        if entry is None:
            rows.append([esc(label), badge(NA), muted("Not present in this run.")])
            continue
        reason = entry.get("reason") if isinstance(entry, dict) else entry
        raw_status = entry.get("status", "") if isinstance(entry, dict) else ""
        rows.append(
            [
                esc(label),
                f"{badge(st)} <code>{esc(raw_status)}</code>",
                fmt_value(reason) if reason else muted("No issues reported."),
            ]
        )
    body = table(["Run", "Status", "Reason / detail"], rows)
    return details(name, overall, body, extra=extra, top_level=True), overall


def section_readiness(pre_state: Dict, post_state: Optional[Dict]) -> Tuple[str, List[str]]:
    pre = normalise_checks(pre_state.get("readiness_checks"))
    post = normalise_checks(post_state.get("readiness_checks")) if post_state else {}
    names = list(dict.fromkeys(list(pre) + list(post)))
    if not names:
        return muted("No readiness checks recorded."), []
    items, statuses = [], []
    for n in names:
        h, s = render_check_pair(n, pre.get(n), post.get(n), post_state is not None)
        items.append(h)
        statuses.append(s)
    return "".join(items), statuses


# --------------------------------------------------------------------------- #
# Section: snapshot capture status
# --------------------------------------------------------------------------- #
def snapshot_size(entry: Any) -> str:
    if isinstance(entry, dict):
        snap = entry.get("snapshot")
        if isinstance(snap, (dict, list)):
            return f"{len(snap)} entries"
        if snap is None:
            return "no data"
    return ""


def section_capture(pre_state: Dict, post_state: Optional[Dict]) -> Tuple[str, List[str]]:
    pre = normalise_checks(pre_state.get("state_snapshot"))
    post = normalise_checks(post_state.get("state_snapshot")) if post_state else {}
    names = list(dict.fromkeys(list(pre) + list(post)))
    if not names:
        return muted("No state snapshots recorded."), []

    items, statuses = [], []
    has_post = post_state is not None
    for n in names:
        p, q = pre.get(n), post.get(n)
        pre_s = check_status(p) if p is not None else NA
        post_s = check_status(q) if q is not None else NA
        overall = worst([pre_s, post_s]) if has_post else pre_s

        extra = f'<span class="lbl">Pre</span>{badge(pre_s)}<span class="cnt">{esc(snapshot_size(p))}</span>'
        if has_post:
            extra += f'<span class="lbl">Post</span>{badge(post_s)}<span class="cnt">{esc(snapshot_size(q))}</span>'

        rows = []
        for label, entry, st in (("Pre-check", p, pre_s), ("Post-check", q, post_s)):
            if label == "Post-check" and not has_post:
                continue
            reason = entry.get("reason") if isinstance(entry, dict) else entry
            rows.append(
                [
                    esc(label),
                    badge(st),
                    fmt_value(reason) if reason else muted("Captured successfully."),
                    esc(snapshot_size(entry)),
                ]
            )
        body = table(["Run", "Status", "Reason", "Size"], rows)
        for label, entry in (("Pre-check raw snapshot", p), ("Post-check raw snapshot", q)):
            if isinstance(entry, dict) and entry.get("snapshot") is not None:
                body += json_block(entry["snapshot"], label)
        items.append(details(n, overall, body, extra=extra, top_level=True))
        statuses.append(overall)
    return "".join(items), statuses


# --------------------------------------------------------------------------- #
# Section: native snapshot comparison
# --------------------------------------------------------------------------- #
def render_key_list(title: str, keys: List[Any]) -> str:
    lis = "".join(f"<li><code>{esc(k)}</code></li>" for k in keys)
    return f'<div class="diffblock fail"><h4>{esc(title)} ({len(keys)})</h4><ul>{lis}</ul></div>'


def render_changed(raw: Dict[str, Any], depth: int) -> str:
    leaf_rows, nested = [], []
    for key, val in raw.items():
        if isinstance(val, dict) and ("left_snap" in val or "right_snap" in val):
            leaf_rows.append(
                [
                    f"<code>{esc(key)}</code>",
                    f'<span class="old">{fmt_value(val.get("left_snap"))}</span>',
                    f'<span class="new">{fmt_value(val.get("right_snap"))}</span>',
                ]
            )
        else:
            nested.append(render_compare_node(key, val, depth + 1))
    out = ""
    if leaf_rows:
        out += '<div class="diffblock fail"><h4>Changed values</h4>'
        out += table(["Property", "Pre-check", "Post-check"], leaf_rows) + "</div>"
    out += "".join(nested)
    return out


def render_compare_node(name: str, node: Any, depth: int = 0) -> str:
    top = depth == 0
    if node is None:
        return details(
            name,
            NA,
            muted(
                "Not evaluated - the comparison returned no result "
                "(e.g. session_stats without 'thresholds' configured)."
            ),
            top_level=top,
        )
    if not isinstance(node, dict):
        return details(name, INFO, fmt_value(node), top_level=top)

    passed = node.get("passed")
    status = PASS if passed is True else FAIL if passed is False else INFO

    parts: List[str] = []
    metric_rows: List[List[str]] = []
    for key, val in node.items():
        if key == "passed":
            continue
        if key == "missing" and isinstance(val, dict):
            if val.get("missing_keys"):
                parts.append(render_key_list("Missing in post-check", val["missing_keys"]))
        elif key == "added" and isinstance(val, dict):
            if val.get("added_keys"):
                parts.append(render_key_list("Added in post-check", val["added_keys"]))
        elif key == "changed" and isinstance(val, dict):
            raw = val.get("changed_raw") or {}
            if raw:
                parts.append(render_changed(raw, depth))
        elif isinstance(val, dict) and "change_percentage" in val:
            m_status = PASS if val.get("passed") is True else FAIL if val.get("passed") is False else INFO
            metric_rows.append(
                [
                    f"<code>{esc(key)}</code>",
                    esc(f'{val.get("change_percentage")}%'),
                    esc(f'{val.get("change_threshold")}%'),
                    badge(m_status),
                ]
            )
        else:
            parts.append(f"<h4>{esc(key)}</h4>{fmt_value(val)}")

    if metric_rows:
        parts.insert(0, table(["Metric", "Change", "Allowed threshold", "Result"], metric_rows))
    if not parts:
        parts.append(muted("No differences between pre- and post-check."))

    # Nested failing nodes open automatically so expanding a failed area
    # immediately reveals the full path down to the changed values.
    return details(name, status, "".join(parts), open_=(not top and status == FAIL), top_level=top)


def section_comparison(
    comparison: Optional[Dict], pre_state: Dict, post_state: Optional[Dict]
) -> Tuple[str, List[str]]:
    if comparison is None:
        return muted("No comparison file found - run the post-check to generate one."), []

    native = comparison.get("native_snapshot_comparison")
    if not isinstance(native, dict) or not native:
        return muted("No snapshot comparison data."), []
    if "error" in native and len(native) == 1:
        return details("Snapshot comparison", ERROR, fmt_value(native["error"]), open_=True, top_level=True), [ERROR]
    if "note" in native and len(native) == 1:
        return details("Snapshot comparison", SKIP, fmt_value(native["note"]), open_=True, top_level=True), [SKIP]

    items, statuses = [], []
    for area, result in native.items():
        items.append(render_compare_node(area, result))
        statuses.append(
            NA if result is None
            else PASS if isinstance(result, dict) and result.get("passed") is True
            else FAIL if isinstance(result, dict) and result.get("passed") is False
            else INFO
        )

    # Areas that were captured but not compared (e.g. capture failed on one side).
    pre_snap = normalise_checks(pre_state.get("state_snapshot"))
    post_snap = normalise_checks((post_state or {}).get("state_snapshot"))
    for area in dict.fromkeys(list(pre_snap) + list(post_snap)):
        if area in native:
            continue
        reasons = []
        for label, snap in (("Pre-check", pre_snap), ("Post-check", post_snap)):
            entry = snap.get(area)
            if entry is None:
                reasons.append([esc(label), muted("Area not captured.")])
            elif isinstance(entry, dict) and entry.get("snapshot") is None:
                reasons.append([esc(label), fmt_value(entry.get("reason") or "No data captured.")])
        body = muted("This area was not compared because usable data was not available on both sides.")
        if reasons:
            body += table(["Run", "Reason"], reasons)
        items.append(details(area, SKIP, body, extra='<span class="flag">not compared</span>', top_level=True))
        statuses.append(SKIP)

    return "".join(items), statuses


# --------------------------------------------------------------------------- #
# Section: custom op checks
# --------------------------------------------------------------------------- #
def section_custom(pre_state: Dict, post_state: Optional[Dict], comparison: Optional[Dict]) -> Tuple[str, List[str]]:
    pre = pre_state.get("custom_checks") or {}
    post = (post_state or {}).get("custom_checks") or {}
    diff = (comparison or {}).get("custom_check_comparison") or {}
    names = list(dict.fromkeys(list(pre) + list(post)))
    if not names:
        return muted("No custom op-command checks configured."), []

    items, statuses = [], []
    for n in names:
        p, q = pre.get(n), post.get(n)
        errs = [
            (label, e["error"])
            for label, e in (("Pre-check", p), ("Post-check", q))
            if isinstance(e, dict) and "error" in e
        ]
        if errs:
            status = ERROR
        elif n in diff.get("changed", {}) or n in diff.get("added", {}) or n in diff.get("removed", {}):
            status = FAIL
        else:
            status = PASS

        body = ""
        if errs:
            body += table(["Run", "Error"], [[esc(l), fmt_value(e)] for l, e in errs])
        if n in diff.get("changed", {}):
            body += '<div class="diffblock fail"><h4>Output changed between pre and post</h4></div>'
        if n in diff.get("added", {}):
            body += '<div class="diffblock fail"><h4>Only present in post-check</h4></div>'
        if n in diff.get("removed", {}):
            body += '<div class="diffblock fail"><h4>Missing from post-check</h4></div>'
        if not body:
            body = muted("No differences between pre- and post-check.")
        if p is not None:
            body += json_block(p, "Pre-check output")
        if q is not None:
            body += json_block(q, "Post-check output")
        items.append(details(n, status, body, top_level=True))
        statuses.append(status)
    return "".join(items), statuses


# --------------------------------------------------------------------------- #
# Device model
# --------------------------------------------------------------------------- #
# (full title, short label used in the overview table / device header)
SECTION_TITLES: List[Tuple[str, str]] = [
    ("Readiness checks", "Readiness"),
    ("Snapshot capture", "Capture"),
    ("Snapshot comparison (pre vs. post)", "Comparison"),
    ("Custom op-command checks", "Custom"),
]


@dataclass
class Device:
    prefix: str
    pre_path: str
    post_path: Optional[str] = None
    comp_path: Optional[str] = None
    pre_state: Optional[Dict] = None
    post_state: Optional[Dict] = None
    comparison: Optional[Dict] = None
    load_errors: List[str] = field(default_factory=list)
    # [(title, short, html, statuses)]
    sections: List[Tuple[str, str, str, List[str]]] = field(default_factory=list)

    @property
    def change_record(self) -> str:
        return change_record_of(self.prefix)

    @property
    def hostname(self) -> str:
        # The filename prefix is the device's identity (unique per file set),
        # so prefer it over metadata, which could be duplicated or missing.
        from_prefix = self.prefix.partition("_")[2]
        meta = (self.pre_state or {}).get("metadata", {})
        return from_prefix or meta.get("hostname") or self.prefix

    @property
    def overall(self) -> str:
        if self.load_errors:
            return ERROR
        return worst(s for *_, sts in self.sections for s in sts)

    def section_status(self, short: str) -> str:
        for _, s, _, sts in self.sections:
            if s == short:
                return worst(sts)
        return NA


def change_record_of(prefix: str) -> str:
    """``<change_record>_<hostname>`` -> ``<change_record>``."""
    return prefix.split("_", 1)[0]


def try_load(path: Optional[str]) -> Tuple[Optional[Dict], Optional[str]]:
    if not path or not os.path.isfile(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None, f"{os.path.basename(path)}: top-level JSON is not an object"
        return data, None
    except Exception as exc:  # noqa: BLE001
        return None, f"{os.path.basename(path)}: {exc}"


def load_device(prefix: str, pre: str, post: Optional[str], comp: Optional[str]) -> Device:
    dev = Device(prefix=prefix, pre_path=pre, post_path=post, comp_path=comp)

    dev.pre_state, err = try_load(pre)
    if err:
        dev.load_errors.append(err)
    elif dev.pre_state is None:
        dev.load_errors.append(f"Pre-check file not found: {pre}")

    dev.post_state, err = try_load(post)
    if err:
        dev.load_errors.append(err)
    dev.comparison, err = try_load(comp)
    if err:
        dev.load_errors.append(err)

    if dev.pre_state is not None:
        pre_s, post_s, comp_d = dev.pre_state, dev.post_state, dev.comparison
        rendered = [
            section_readiness(pre_s, post_s),
            section_capture(pre_s, post_s),
            section_comparison(comp_d, pre_s, post_s),
            section_custom(pre_s, post_s, comp_d),
        ]
        dev.sections = [
            (title, short, content, sts)
            for (title, short), (content, sts) in zip(SECTION_TITLES, rendered)
        ]
    return dev


def natural_key(text: str) -> List[Any]:
    """Sort '192.168.4.9' before '192.168.4.16'."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", text)]


# --------------------------------------------------------------------------- #
# Page assembly
# --------------------------------------------------------------------------- #
CSS = """
:root{color-scheme:light;
--pass:#1e8e3e;--fail:#d93025;--error:#e37400;--skip:#80868b;--na:#9aa0a6;--info:#1a73e8;
--bg:#f6f8fa;--card:#fff;--line:#dfe3e8;--text:#202124;--muted:#5f6368;
--th:#f1f3f4;--code-bg:#f8f9fa;--header-bg:#202124;--header-text:#fff;--header-muted:#c8cdd2;
--active-bg:#202124;--active-text:#fff;
--flag-bg:#fef7e0;--flag-text:#8a5a00;--flag-line:#f9d77e}
:root[data-theme="dark"]{color-scheme:dark;
--pass:#2e9e4f;--fail:#e5483b;--error:#e88a1a;--skip:#7d838c;--na:#5f6368;--info:#6ea2ff;
--bg:#0f1115;--card:#1a1d23;--line:#2f343c;--text:#e6e8eb;--muted:#9aa0a6;
--th:#23272e;--code-bg:#13161b;--header-bg:#000;--header-text:#f1f3f4;--header-muted:#9aa0a6;
--active-bg:#e6e8eb;--active-text:#0f1115;
--flag-bg:#3a2f10;--flag-text:#f6c453;--flag-line:#6b5414}
*{box-sizing:border-box}
body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:var(--bg);color:var(--text);font-size:14px}
header{background:var(--header-bg);color:var(--header-text);padding:18px 28px;position:sticky;top:0;z-index:5}
header h1{margin:0 0 6px;font-size:20px}
header .meta{display:flex;flex-wrap:wrap;gap:22px;color:var(--header-muted);font-size:13px}
header .meta b{color:var(--header-text)}
main{padding:20px 28px;max-width:1400px;margin:auto}
.toolbar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.toolbar button,.toolbar select{border:1px solid var(--line);background:var(--card);color:var(--text);
padding:6px 12px;border-radius:6px;cursor:pointer;font:inherit}
.toolbar button.active{background:var(--active-bg);color:var(--active-text)}
.toolbar input{border:1px solid var(--line);background:var(--card);color:var(--text);padding:6px 10px;
border-radius:6px;min-width:240px;font:inherit}
.toolbar .spacer{flex:1}
.toolbar label{color:var(--muted);font-size:13px;display:flex;align-items:center;gap:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;border-left:6px solid var(--na)}
.card.pass{border-left-color:var(--pass)}.card.fail{border-left-color:var(--fail)}
.card.error{border-left-color:var(--error)}.card.skip{border-left-color:var(--skip)}
.card h3{margin:0 0 6px;font-size:14px}
.card .counts span{margin-right:10px;font-size:13px;display:inline-block;margin-bottom:4px}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin-bottom:18px}
section>h2{margin:0 0 10px;font-size:16px;display:flex;align-items:center;gap:10px}
details.device{background:var(--card);border:1px solid var(--line);border-left:8px solid var(--na);
border-radius:8px;margin-bottom:14px;scroll-margin-top:110px}
details.device.pass{border-left-color:var(--pass)}details.device.fail{border-left-color:var(--fail)}
details.device.error{border-left-color:var(--error)}details.device.skip{border-left-color:var(--skip)}
details.device>summary{cursor:pointer;padding:12px 16px;display:flex;align-items:center;gap:10px;
list-style:none;font-size:15px}
details.device>summary::-webkit-details-marker{display:none}
details.device>summary::before{content:"\\25B6";font-size:11px;color:var(--muted);transition:transform .15s}
details.device[open]>summary::before{transform:rotate(90deg)}
details.device>summary .name{font-weight:700;font-family:Consolas,monospace}
details.device>summary .extra{margin-left:auto;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
details.device>.body{padding:4px 16px 16px;border-top:1px solid var(--line)}
details.device section{border:none;border-bottom:1px solid var(--line);border-radius:0;padding:10px 0;margin:0}
details.device section:last-child{border-bottom:none}
details.device section>h2{font-size:15px}
.devmeta{display:flex;flex-wrap:wrap;gap:18px;color:var(--muted);font-size:12px;margin:8px 0 4px}
.devmeta b{color:var(--text)}
details.item{border:1px solid var(--line);border-left:5px solid var(--na);border-radius:6px;margin:6px 0;background:var(--card)}
details.item.pass{border-left-color:var(--pass)}details.item.fail{border-left-color:var(--fail)}
details.item.error{border-left-color:var(--error)}details.item.skip{border-left-color:var(--skip)}
details.item.info{border-left-color:var(--info)}
details.item>summary{cursor:pointer;padding:8px 10px;display:flex;align-items:center;gap:10px;list-style:none}
details.item>summary::-webkit-details-marker{display:none}
details.item>summary::before{content:"\\25B6";font-size:10px;color:var(--muted);transition:transform .15s}
details.item[open]>summary::before{transform:rotate(90deg)}
details.item>summary .name{font-weight:600;font-family:Consolas,monospace}
details.item>summary .extra{margin-left:auto;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
details.item .body{padding:4px 14px 12px 30px;border-top:1px dashed var(--line)}
details.item details.item{margin-left:4px}
.badge{display:inline-block;min-width:62px;text-align:center;padding:2px 8px;border-radius:10px;
font-size:11px;font-weight:700;color:#fff;background:var(--na)}
.badge.pass{background:var(--pass)}.badge.fail{background:var(--fail)}.badge.error{background:var(--error)}
.badge.skip{background:var(--skip)}.badge.info{background:var(--info)}
.lbl{font-size:11px;color:var(--muted);margin-left:6px}
.cnt{font-size:11px;color:var(--muted)}
.flag{font-size:11px;background:var(--flag-bg);color:var(--flag-text);border:1px solid var(--flag-line);padding:1px 6px;border-radius:8px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--th);font-weight:600}
table.overview td{vertical-align:middle}
table.overview a{font-family:Consolas,monospace;font-weight:600;color:var(--info);text-decoration:none}
table.overview a:hover{text-decoration:underline}
pre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:Consolas,monospace;font-size:12px}
code{font-family:Consolas,monospace;font-size:12px}
.old{color:var(--fail)}.new{color:var(--pass)}
.muted{color:var(--muted);margin:6px 0}
.diffblock{margin:8px 0}.diffblock h4{margin:4px 0;font-size:13px;color:var(--fail)}
.diffblock ul{margin:4px 0 4px 18px;padding:0}
details.raw{margin:6px 0}details.raw>summary{cursor:pointer;color:var(--info);font-size:12px}
details.raw pre{background:var(--code-bg);border:1px solid var(--line);padding:8px;max-height:400px;overflow:auto;margin-top:4px}
body.failures-only details.item.top.pass,body.failures-only details.item.top.na,
body.failures-only details.device.pass,body.failures-only table.overview tr.pass{display:none}
.hidden-by-filter{display:none !important}
footer{color:var(--muted);font-size:12px;text-align:center;padding:10px 0 24px}
"""

JS = """
/* ---- Theme handling -------------------------------------------------------
   Choice order: user's saved choice (localStorage) -> default baked in at
   generation time (--theme) -> 'auto' (follow the OS light/dark setting).
   This script runs in <head> so the theme is applied before first paint. */
var THEME_KEY='uaReportTheme';
function effectiveTheme(choice){
  if(choice==='light'||choice==='dark'){return choice;}
  return (window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';
}
function applyTheme(choice){
  var root=document.documentElement;
  root.setAttribute('data-theme-choice',choice);
  root.setAttribute('data-theme',effectiveTheme(choice));
  var sel=document.getElementById('themeSelect');
  if(sel){sel.value=choice;}
}
function savedTheme(){
  var def=document.documentElement.getAttribute('data-default-theme')||'auto';
  try{return localStorage.getItem(THEME_KEY)||def;}catch(e){return def;}
}
function setTheme(choice){
  try{localStorage.setItem(THEME_KEY,choice);}catch(e){}
  applyTheme(choice);
}
applyTheme(savedTheme());
if(window.matchMedia){
  var mq=window.matchMedia('(prefers-color-scheme: dark)');
  var onOsChange=function(){
    if(document.documentElement.getAttribute('data-theme-choice')==='auto'){applyTheme('auto');}
  };
  if(mq.addEventListener){mq.addEventListener('change',onOsChange);}else if(mq.addListener){mq.addListener(onOsChange);}
}
document.addEventListener('DOMContentLoaded',function(){applyTheme(savedTheme());});

/* ---- Expand / filter controls ------------------------------------------- */
function setAll(open){document.querySelectorAll('details.item,details.device').forEach(d=>d.open=open);}
function setDevices(open){document.querySelectorAll('details.device').forEach(d=>d.open=open);}
function toggleFailures(btn){document.body.classList.toggle('failures-only');btn.classList.toggle('active');}
function openDev(id){var d=document.getElementById(id);if(d){d.open=true;}}
function filterDevices(q){
  q=q.trim().toLowerCase();
  document.querySelectorAll('[data-host]').forEach(function(el){
    el.classList.toggle('hidden-by-filter', q!=='' && el.getAttribute('data-host').indexOf(q)===-1);
  });
}
"""


def summary_card(title: str, statuses: List[str], unit: str = "") -> str:
    counts: Dict[str, int] = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1
    parts = "".join(
        f"<span>{badge(s)} {counts[s]}{esc(unit)}</span>"
        for s in (PASS, FAIL, ERROR, SKIP, NA, INFO)
        if counts.get(s)
    ) or muted("No data")
    return f'<div class="card {worst(statuses)}"><h3>{esc(title)}</h3><div class="counts">{parts}</div></div>'


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #
# Every timestamp in the report (pre-check, post-check, comparison and
# "Generated") is rendered in this format, in the local timezone of the
# machine running this generator, with an explicit UTC offset.
TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_ts(value: Any) -> Optional[dt.datetime]:
    """Parse the timestamps written by the pre/post check script.

    That script writes ``isoformat() + "Z"`` on an already offset-aware value,
    producing e.g. ``2026-10-02T15:47:45.953384+00:00Z``. Plain ``...Z``,
    ``...+00:00`` and naive (assumed UTC) ISO strings are accepted too.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    if s[-1] in "Zz":
        s = s[:-1]
        if not re.search(r"[+-]\d{2}:?\d{2}$", s):
            s += "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def fmt_dt(value: dt.datetime) -> str:
    """``2026-10-02 11:47:45 (UTC-04:00)`` in the local timezone."""
    local = value.astimezone()
    off = local.strftime("%z") or "+0000"
    return f"{local.strftime(TS_FORMAT)} (UTC{off[:3]}:{off[3:5]})"


def fmt_ts(value: Any, default: str) -> str:
    """Format a raw timestamp string; unparseable values are shown as-is."""
    parsed = parse_ts(value)
    if parsed is not None:
        return fmt_dt(parsed)
    return str(value) if value else default


def ts(state: Optional[Dict], default: str) -> str:
    return fmt_ts((state or {}).get("metadata", {}).get("timestamp"), default)


def render_overview(devices: List[Device]) -> str:
    headers = ["Device", "Overall"] + [short for _, short in SECTION_TITLES] + ["Pre-check", "Post-check"]
    rows, row_attrs = [], []
    for i, dev in enumerate(devices):
        anchor = f"dev-{i}"
        row = [
            f'<a href="#{anchor}" onclick="openDev(\'{anchor}\')">{esc(dev.hostname)}</a>',
            badge(dev.overall),
        ]
        row += [badge(dev.section_status(short)) for _, short in SECTION_TITLES]
        row += [
            esc(ts(dev.pre_state, "-")),
            esc(ts(dev.post_state, "not run") if dev.post_state else "not run"),
        ]
        rows.append(row)
        # class drives "Show only issues"; data-host drives the filter box.
        row_attrs.append(f'class="{dev.overall}" data-host="{esc(dev.hostname.lower())}"')
    return table(headers, rows, cls="overview", row_attrs=row_attrs)


def render_device(dev: Device, idx: int, open_: bool) -> str:
    anchor = f"dev-{idx}"
    extra = "".join(
        f'<span class="lbl">{esc(short)}</span>{badge(dev.section_status(short))}'
        for _, short in SECTION_TITLES
    )

    meta_items = [
        ("Prefix", dev.prefix),
        ("Pre-check", ts(dev.pre_state, "-")),
        ("Post-check", ts(dev.post_state, "not run") if dev.post_state else "not run"),
        ("Comparison", fmt_ts((dev.comparison or {}).get("timestamp"), "n/a")),
    ]
    body = '<div class="devmeta">' + "".join(
        f"<span>{esc(k)}: <b>{esc(v)}</b></span>" for k, v in meta_items
    ) + "</div>"

    if dev.load_errors:
        body += (
            f"<section><h2>{badge(ERROR)} File load errors</h2>"
            + table(["Problem"], [[fmt_value(e)] for e in dev.load_errors])
            + "</section>"
        )

    for title, _, content, sts in dev.sections:
        body += f"<section><h2>{badge(worst(sts))} {esc(title)}</h2>{content}</section>"

    ignored = (dev.comparison or {}).get("ignored_keys")
    if ignored:
        body += (
            "<section><h2>Ignored keys</h2>"
            + muted("These keys were excluded from the comparison and cannot cause a failure.")
            + json_block(ignored, "Show ignored keys")
            + "</section>"
        )

    return (
        f'<details class="device {dev.overall}" id="{anchor}" '
        f'data-host="{esc(dev.hostname.lower())}"{" open" if open_ else ""}>'
        f'<summary>{badge(dev.overall)}<span class="name">{esc(dev.hostname)}</span>'
        f'<span class="extra">{extra}</span></summary>'
        f'<div class="body">{body}</div></details>'
    )


THEMES = ("auto", "light", "dark")


def build_html(title_key: str, devices: List[Device], theme: str = "auto") -> str:
    theme = theme if theme in THEMES else "auto"
    devices = sorted(devices, key=lambda d: natural_key(d.hostname))
    overall = worst(d.overall for d in devices)
    single = len(devices) == 1
    with_issues = sum(1 for d in devices if d.overall != PASS)

    change_records = sorted({d.change_record for d in devices})
    generated = fmt_dt(dt.datetime.now(dt.timezone.utc))
    meta = [
        ("Change record", ", ".join(change_records) or "-"),
        ("Devices", str(len(devices))),
        ("Devices with issues", str(with_issues)),
        ("Post-checks run", f"{sum(1 for d in devices if d.post_state)}/{len(devices)}"),
        ("Generated", generated),
    ]
    meta_html = "".join(f"<span>{esc(k)}: <b>{esc(v)}</b></span>" for k, v in meta)

    cards = summary_card("Devices (overall)", [d.overall for d in devices], "")
    for title, short in SECTION_TITLES:
        sts = [s for d in devices for (_, sh, _, ss) in d.sections if sh == short for s in ss]
        cards += summary_card(f"{short} - all devices", sts)

    overview = (
        f"<section><h2>{badge(overall)} Device overview</h2>"
        + muted("Click a device name to jump to its details.")
        + render_overview(devices)
        + "</section>"
    )

    device_blocks = "".join(
        render_device(d, i, open_=single) for i, d in enumerate(devices)
    )

    return f"""<!DOCTYPE html>
<html lang="en" data-default-theme="{theme}" data-theme="{'dark' if theme == 'dark' else 'light'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title_key)} - Upgrade Assurance Report</title>
<style>{CSS}</style><script>{JS}</script></head>
<body>
<header><h1>{badge(overall)} Upgrade Assurance Report - {esc(title_key)}</h1>
<div class="meta">{meta_html}</div></header>
<main>
<div class="toolbar">
<button onclick="setDevices(true)">Expand devices</button>
<button onclick="setAll(true)">Expand everything</button>
<button onclick="setAll(false)">Collapse all</button>
<button onclick="toggleFailures(this)">Show only issues</button>
<input type="search" placeholder="Filter devices by hostname..." oninput="filterDevices(this.value)">
<span class="spacer"></span>
<label for="themeSelect">Theme
<select id="themeSelect" onchange="setTheme(this.value)">
<option value="auto">System</option>
<option value="light">Light</option>
<option value="dark">Dark</option>
</select></label>
</div>
<div class="cards">{cards}</div>
{overview}
{device_blocks}
</main>
<footer>Generated {esc(generated)} by generate_html_report.py</footer>
</body></html>
"""


# --------------------------------------------------------------------------- #
# File discovery / CLI
# --------------------------------------------------------------------------- #
def discover_prefixes(directory: str) -> List[str]:
    return sorted(
        os.path.basename(p)[: -len(PRE_SUFFIX)]
        for p in glob.glob(os.path.join(directory, f"*{PRE_SUFFIX}"))
    )


def group_by_change(prefixes: List[str], selectors: List[str]) -> Dict[str, List[str]]:
    """Group device prefixes by change record.

    A selector matches a prefix if it equals it (single device) or is its
    change record (``CHG1234`` matches ``CHG1234_<any host>``).
    """
    groups: Dict[str, List[str]] = {}
    for prefix in prefixes:
        if selectors and not any(
            prefix == sel or prefix.startswith(f"{sel}_") for sel in selectors
        ):
            continue
        groups.setdefault(change_record_of(prefix), []).append(prefix)
    return groups


def write_report(title_key: str, devices: List[Device], out: str, theme: str = "auto") -> str:
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(build_html(title_key, devices, theme))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render pre/post upgrade check JSON as a combined HTML report per change record."
    )
    parser.add_argument(
        "selectors",
        nargs="*",
        metavar="CHANGE_RECORD",
        help="Change record(s) such as 'CHG1234' (all devices) or a full '<change>_<host>' prefix "
        "(single device). If omitted, one report is built for every change record in the directory.",
    )
    parser.add_argument("--dir", default=".", help="Directory containing the JSON files (default: cwd).")
    parser.add_argument("--pre", help="Explicit pre-check JSON path (single-device mode).")
    parser.add_argument("--post", help="Explicit post-check JSON path (single-device mode).")
    parser.add_argument("--comparison", help="Explicit comparison JSON path (single-device mode).")
    parser.add_argument(
        "--theme",
        choices=THEMES,
        default="auto",
        help="Default colour theme of the report (default: auto = follow the viewer's OS setting). "
        "Viewers can still switch with the Theme selector; their choice is remembered by the browser.",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output HTML path. Only honoured when exactly one report is produced "
        "(default: <change_record>_report.html in --dir).",
    )
    args = parser.parse_args(argv)

    # ---- Explicit single-device mode -------------------------------------
    if args.pre:
        base = os.path.basename(args.pre)
        prefix = args.selectors[0] if args.selectors else base.replace(PRE_SUFFIX, "").replace(".json", "")
        dev = load_device(prefix, args.pre, args.post, args.comparison)
        out = args.output or os.path.join(os.path.dirname(args.pre) or ".", f"{prefix}_report.html")
        print(
            f"Report written: {write_report(prefix, [dev], out, args.theme)}  "
            f"(1 device, {STATUS_LABEL[dev.overall]})"
        )
        return 1 if dev.load_errors else 0

    # ---- Discovery mode: one combined report per change record -----------
    groups = group_by_change(discover_prefixes(args.dir), args.selectors)
    if not groups:
        wanted = ", ".join(args.selectors) if args.selectors else "any change record"
        print(f"No *{PRE_SUFFIX} files found in '{args.dir}' for {wanted}.", file=sys.stderr)
        return 1

    if args.output and len(groups) > 1:
        print(
            f"--output ignored: {len(groups)} change records matched; writing one report per change record.",
            file=sys.stderr,
        )

    rc = 0
    for change, prefixes in sorted(groups.items()):
        devices = []
        for prefix in prefixes:
            base = os.path.join(args.dir, prefix)
            dev = load_device(prefix, base + PRE_SUFFIX, base + POST_SUFFIX, base + COMP_SUFFIX)
            if dev.load_errors:
                for err in dev.load_errors:
                    print(f"[{prefix}] {err}", file=sys.stderr)
                rc = 1
            devices.append(dev)

        # If the user selected a single full prefix, title the report with it.
        title_key = prefixes[0] if (len(prefixes) == 1 and prefixes[0] in args.selectors) else change
        out = (
            args.output
            if (args.output and len(groups) == 1)
            else os.path.join(args.dir, f"{title_key}_report.html")
        )
        try:
            write_report(title_key, devices, out, args.theme)
        except Exception as exc:  # noqa: BLE001
            print(f"[{change}] Failed to build report: {exc}", file=sys.stderr)
            rc = 1
            continue

        tally: Dict[str, int] = {}
        for d in devices:
            tally[d.overall] = tally.get(d.overall, 0) + 1
        tally_txt = ", ".join(f"{STATUS_LABEL[s]}: {n}" for s, n in sorted(tally.items(), key=lambda kv: -SEVERITY[kv[0]]))
        print(f"Report written: {out}  ({len(devices)} device(s) - {tally_txt})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
