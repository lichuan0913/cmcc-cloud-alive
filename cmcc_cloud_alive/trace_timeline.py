"""Build compact timelines from ZIME probe JSONL traces.

The probe records several layers in one process tree.  This module keeps the
analysis conservative: it does not guess missing protocol fields, it only groups
records by observable peer/direction/function and by the same payload classifier
used by :mod:`zime_probe`.
"""

import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from . import core, zime_probe


IMPORTANT_KINDS = {
    "spice-link",
    "spice-main-init",
    "spice-channels-list",
    "spice-display-init",
    "spice-surface-create",
    "spice-draw-copy",
    "spice-mark",
    "spice-set-ack",
    "spice-ack-sync",
    "spice-ping",
    "spice-pong",
    "spice-ack",
}


def peer_group(peer):
    """Return a stable coarse peer group for timeline aggregation."""
    text = str(peer or "")
    if text == "-":
        return "unknown"
    if text.startswith("family:"):
        return "family"
    if text.startswith("127.") or text.startswith("localhost") or text.startswith("::1"):
        return "loopback"
    if text.startswith("/") or text.startswith("unix:"):
        return "unix"
    if not text:
        return "unknown"
    return "external"


def record_peer(record):
    peer = record.get("peer")
    if peer and peer != "-":
        return peer
    return record.get("remote") or peer


def _hex_to_bytes(record):
    value = record.get("hex") or ""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def _event_time(record):
    sec = record.get("sec") or 0
    nsec = record.get("nsec") or 0
    try:
        return float(sec) + float(nsec) / 1_000_000_000
    except (TypeError, ValueError):
        return 0.0


def _load_jsonl(path):
    records = []
    invalid = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as err:
            invalid.append({"line": line_number, "error": str(err), "text": line[:200]})
    return records, invalid


def _record_kind(record):
    data = _hex_to_bytes(record)
    computed = zime_probe.classify_payload(data, allow_short_mini=record.get("event") == "ssl_buffer")
    recorded = str(record.get("payloadKind") or "")
    if computed.startswith("tls-"):
        return computed
    if recorded and recorded != "unknown":
        return recorded
    return computed if computed != "unknown" else (recorded or computed)


def timeline(path, *, limit=80, include_unknown=False, report_file=None):
    """Analyze a ZIME JSONL file into grouped counters and key event timeline."""
    records, invalid = _load_jsonl(path)
    counters = defaultdict(Counter)
    examples = {}
    events = []
    first_time = None

    for index, record in enumerate(records, 1):
        event = record.get("event")
        if event not in {"transport_buffer", "zime_buffer", "ssl_buffer"}:
            continue
        direction = record.get("direction") or "unknown"
        function = record.get("function") or "unknown"
        peer = record_peer(record)
        group = peer_group(peer)
        kind = _record_kind(record)
        key = f"{group}|{direction}|{function}"
        counters[key][kind] += 1
        examples.setdefault((key, kind), {
            "index": index,
            "peer": peer,
            "rawPeer": record.get("peer"),
            "remote": record.get("remote"),
            "fd": record.get("fd"),
            "len": record.get("len"),
            "ret": record.get("ret"),
            "hexPrefix": str(record.get("hex") or "")[:160],
        })
        is_important = kind in IMPORTANT_KINDS or kind.startswith("chuanyun-frame")
        if is_important or (include_unknown and kind == "unknown"):
            ts = _event_time(record)
            if first_time is None:
                first_time = ts
            events.append({
                "index": index,
                "t": ts,
                "dt": round(ts - first_time, 6) if first_time is not None else 0.0,
                "event": event,
                "function": function,
                "direction": direction,
                "peerGroup": group,
                "peer": peer,
                "rawPeer": record.get("peer"),
                "remote": record.get("remote"),
                "fd": record.get("fd"),
                "len": record.get("len"),
                "ret": record.get("ret"),
                "payloadKind": kind,
                "hexPrefix": str(record.get("hex") or "")[:160],
            })

    grouped = []
    for key in sorted(counters):
        group, direction, function = key.split("|", 2)
        top = [{"payloadKind": kind, "count": count} for kind, count in counters[key].most_common()]
        sample_map = {}
        for kind, _count in counters[key].most_common():
            sample_map[kind] = examples.get((key, kind))
        grouped.append({
            "peerGroup": group,
            "direction": direction,
            "function": function,
            "total": sum(counters[key].values()),
            "payloadKinds": top,
            "examples": sample_map,
        })

    report = {
        "ok": True,
        "inputFile": str(path),
        "records": len(records),
        "invalidLines": invalid,
        "groupedCounters": grouped,
        "keyTimeline": events[: max(0, int(limit))],
        "keyTimelineTotal": len(events),
        "findings": {
            "familyIsNativeTransport": any(item["peerGroup"] == "family" for item in grouped),
            "loopbackHasPlainSpice": any(
                item["peerGroup"] == "loopback" and any(k["payloadKind"].startswith("spice-") for k in item["payloadKinds"])
                for item in grouped
            ),
            "displayPathObserved": any(e["payloadKind"] in {"spice-display-init", "spice-surface-create", "spice-draw-copy", "spice-mark"} for e in events),
            "chuanyunOnFamilyObserved": any(
                item["peerGroup"] == "family"
                and any(k["payloadKind"].startswith("chuanyun-frame") for k in item["payloadKinds"])
                for item in grouped
            ),
        },
        "analyzedAt": core.shanghai_now().isoformat(),
    }
    core.write_private_json_report(report, report_file)
    return report
