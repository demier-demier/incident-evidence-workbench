"""Strict event normalization and deterministic, bounded defensive correlations."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

MAX_BYTES = 262_144
MAX_EVENTS = 1_000
MAX_LINE_BYTES = 4_096
BASE = {"timestamp", "tenant", "actor", "type", "source_ip"}
FIELDS = {
    "auth_failure": ({"session"}, set()),
    "auth_success": ({"session"}, set()),
    "role_change": ({"session", "old_role", "new_role"}, {"session", "old_role", "new_role"}),
    "token_use": ({"token_id", "expected_source"}, {"token_id", "expected_source"}),
    "data_access": ({"session", "resource", "classification", "authorized", "records"},
                    {"session", "resource", "classification", "authorized", "records"}),
}
RANK = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}


class InputError(ValueError):
    """Input failed a supported schema or resource limit."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InputError("Duplicate JSON object key")
            result[key] = value
        return result
    def constant(_):
        raise InputError("Non-finite JSON number")
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("Invalid JSON") from exc


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value
    ):
        raise InputError("timestamp must be RFC3339 with a timezone and seconds")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        if not 2000 <= dt.year <= 2100:
            raise ValueError()
        return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise InputError("timestamp must be a valid date from 2000 through 2100") from exc


def seconds(event):
    return datetime.fromisoformat(event["normalized"]["timestamp"].replace("Z", "+00:00")).timestamp()


def normalize(raw):
    if not isinstance(raw, dict):
        raise InputError("Each line must contain one JSON object")
    kind = raw.get("type")
    if not isinstance(kind, str) or kind not in FIELDS:
        raise InputError("Unsupported event type")
    allowed, required = FIELDS[kind]
    if set(raw) - (BASE | allowed):
        raise InputError("Unsupported field for event type")
    if (BASE | required) - set(raw):
        raise InputError("Missing required field")
    normalized = dict(raw)
    for key, value in raw.items():
        if key in {"expected_source", "authorized"}:
            if type(value) is not bool:
                raise InputError(f"{key} must be a boolean")
        elif key == "records":
            if type(value) is not int or not 0 <= value <= 1_000_000:
                raise InputError("records must be an integer from 0 through 1000000")
        else:
            if not isinstance(value, str) or not 1 <= len(value) <= 160 or not value.strip():
                raise InputError(f"{key} must be a nonempty string of at most 160 characters")
            if any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise InputError(f"{key} contains unsupported control characters")
    normalized["timestamp"] = timestamp(raw["timestamp"])
    try:
        if "%" in raw["source_ip"]:
            raise ValueError()
        normalized["source_ip"] = str(ipaddress.ip_address(raw["source_ip"]))
    except ValueError as exc:
        raise InputError("source_ip must be an IP literal without a zone") from exc
    if kind == "role_change" and (raw["old_role"] not in RANK or raw["new_role"] not in RANK):
        raise InputError("role must be viewer, member, admin, or owner")
    if kind == "data_access" and raw["classification"] not in {"public", "internal", "restricted"}:
        raise InputError("classification must be public, internal, or restricted")
    return normalized


def parse_jsonl(text):
    if not isinstance(text, str):
        raise InputError("Input must be UTF-8 JSONL text")
    try:
        raw_bytes = text.encode("utf-8")
    except UnicodeError as exc:
        raise InputError("Invalid UTF-8 text") from exc
    if len(raw_bytes) > MAX_BYTES:
        raise InputError(f"Input exceeds {MAX_BYTES} bytes")
    events, duplicates, count = {}, 0, 0
    # split on LF only: other control characters are not implicit record boundaries.
    for line_number, line in enumerate(text.split("\n"), 1):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise InputError(f"Line {line_number}: exceeds {MAX_LINE_BYTES} bytes")
        if not line.strip():
            continue
        count += 1
        if count > MAX_EVENTS:
            raise InputError(f"Input exceeds {MAX_EVENTS} event lines (duplicates count)")
        try:
            normalized = normalize(strict_json(line))
        except InputError as exc:
            raise InputError(f"Line {line_number}: {exc}") from exc
        digest = hashlib.sha256(canonical(normalized).encode()).hexdigest()
        evidence_id = "ev_" + digest
        if evidence_id in events:
            events[evidence_id]["source_lines"].append(line_number)
            duplicates += 1
        else:
            events[evidence_id] = {"evidence_id": evidence_id, "sha256": digest,
                                   "source_lines": [line_number], "normalized": normalized}
    if not events:
        raise InputError("Provide at least one event")
    return {"events": sorted(events.values(), key=lambda e: (e["normalized"]["timestamp"], e["evidence_id"])),
            "duplicates": duplicates, "input_sha256": hashlib.sha256(raw_bytes).hexdigest()}


RULES = {
    "R01": {"title": "Failure burst followed by successful authentication", "severity": "high",
            "reason": "At least three failed authentications preceded success for the same tenant, actor and source IP within five minutes.",
            "investigation": "Confirm user activity and MFA context; inspect identity-provider records and the successful session before deciding on a response.",
            "limitations": "Typing mistakes and approved tests can match. Distributed or slow attempts and attempts without a recorded success are missed.",
            "attack": ["T1110", "T1078"]},
    "R02": {"title": "Privileged role elevation after authentication", "severity": "high",
            "reason": "A member or viewer became an admin or owner within ten minutes of a matching authenticated session and source IP.",
            "investigation": "Check the approved access request, granting identity, session records and role audit trail; verify whether the change was expected.",
            "limitations": "Planned onboarding can match. Missing session IDs, changing IPs, custom role names and admin-to-owner transitions are outside this rule.",
            "attack": ["T1078"]},
    "R03": {"title": "Token moved from expected to unexpected source", "severity": "medium",
            "reason": "The same token reference was used from an expected source, then from a different source marked unexpected within ten minutes.",
            "investigation": "Verify the source-policy annotation and deployment changes; review token-owner and service audit records. Never paste an actual token secret.",
            "limitations": "NAT, failover and deployments can match. This relies on supplied expected_source labels; it does not learn a network baseline or prove token theft.",
            "attack": ["T1078"]},
    "R04": {"title": "Restricted records returned outside policy", "severity": "high",
            "reason": "A matching authenticated session accessed restricted data marked unauthorized and returned at least one record within ten minutes.",
            "investigation": "Verify the policy decision, resource classification and actual returned-record count against the original access audit; confirm approved exceptions.",
            "limitations": "Incorrect policy labels can match. Zero-record denials, unknown authorization, missing sessions and unclassified resources are not covered.",
            "attack": []},
}


def analyze(text):
    parsed = parse_jsonl(text)
    events = parsed["events"]
    findings = []
    partitions = {}
    for event in events:
        n = event["normalized"]
        partitions.setdefault((n["tenant"], n["actor"]), []).append(event)

    def add(rule, evidence):
        evidence = sorted(evidence, key=lambda e: (seconds(e), e["evidence_id"]))
        ids = [e["evidence_id"] for e in evidence]
        findings.append({**RULES[rule], "rule_id": rule, "evidence_ids": ids,
                         "finding_id": "fi_" + hashlib.sha256(canonical([rule, ids]).encode()).hexdigest(),
                         "start": evidence[0]["normalized"]["timestamp"],
                         "end": evidence[-1]["normalized"]["timestamp"],
                         "tenant": evidence[-1]["normalized"]["tenant"],
                         "actor": evidence[-1]["normalized"]["actor"]})

    for stream in partitions.values():
        for index, current in enumerate(stream):
            n, now = current["normalized"], seconds(current)
            previous = [e for e in stream[:index] if 0 < now - seconds(e) <= 600]
            if n["type"] == "auth_success":
                same = [e for e in previous if e["normalized"]["source_ip"] == n["source_ip"]]
                last_success = max((seconds(e) for e in same if e["normalized"]["type"] == "auth_success"), default=float("-inf"))
                failures = [e for e in same if e["normalized"]["type"] == "auth_failure"
                            and now - seconds(e) <= 300 and seconds(e) > last_success]
                if len(failures) >= 3:
                    add("R01", failures + [current])
            if n["type"] in {"role_change", "data_access"}:
                authenticated = [e for e in previous if e["normalized"]["type"] == "auth_success"
                                 and e["normalized"].get("session") == n["session"]
                                 and e["normalized"]["source_ip"] == n["source_ip"]]
                if authenticated:
                    if n["type"] == "role_change" and RANK[n["old_role"]] <= 1 and RANK[n["new_role"]] >= 2:
                        add("R02", [authenticated[-1], current])
                    if n["type"] == "data_access" and n["classification"] == "restricted" and not n["authorized"] and n["records"] > 0:
                        add("R04", [authenticated[-1], current])
            if n["type"] == "token_use" and not n["expected_source"]:
                expected = [e for e in previous if e["normalized"]["type"] == "token_use"
                            and e["normalized"]["token_id"] == n["token_id"]
                            and e["normalized"]["expected_source"]
                            and e["normalized"]["source_ip"] != n["source_ip"]]
                if expected:
                    add("R03", [expected[-1], current])

    cases = []
    for finding in sorted(findings, key=lambda f: (f["end"], f["finding_id"])):
        end = datetime.fromisoformat(finding["end"].replace("Z", "+00:00"))
        candidates = [c for c in cases if c["tenant"] == finding["tenant"] and c["actor"] == finding["actor"]
                      and 0 <= (end - datetime.fromisoformat(min(c["start"], finding["start"]).replace("Z", "+00:00"))).total_seconds() <= 900]
        case = candidates[-1] if candidates else None
        if case is None:
            case = {"tenant": finding["tenant"], "actor": finding["actor"], "start": finding["start"], "findings": []}
            cases.append(case)
        case["start"] = min(case["start"], finding["start"])
        case["findings"].append(finding)
    event_index = {e["evidence_id"]: e for e in events}
    for case in cases:
        refs = {ref for f in case["findings"] for ref in f["evidence_ids"]}
        case["evidence_ids"] = sorted(refs, key=lambda ref: (seconds(event_index[ref]), ref))
        case["end"] = max(f["end"] for f in case["findings"])
        case["severity"] = "high" if any(f["severity"] == "high" for f in case["findings"]) else "medium"
        case["case_id"] = "case_" + hashlib.sha256(canonical(sorted(f["finding_id"] for f in case["findings"])).encode()).hexdigest()[:20]
    cases.sort(key=lambda c: (c["severity"] != "high", c["start"], c["case_id"]))
    return {**parsed, "schema_version": "1.0", "engine": "deterministic-rules", "model": {"status": "disabled"},
            "incidents": cases, "summary": {"events": len(events), "duplicates": parsed["duplicates"],
            "incidents": len(cases), "findings": len(findings),
            "high": sum(c["severity"] == "high" for c in cases), "medium": sum(c["severity"] == "medium" for c in cases)}}
