"""Behavioral coverage for strict evidence ingestion and deterministic correlation.

Only synthetic fixtures are used. Run with ``python -m unittest discover -s tests``.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from incident_workbench import (
    MAX_BYTES,
    MAX_EVENTS,
    MAX_LINE_BYTES,
    InputError,
    analyze,
    parse_jsonl,
)


START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(kind="auth_success", seconds=0, **overrides):
    item = {
        "timestamp": (START + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
        "tenant": "tenant-a",
        "actor": "actor-a",
        "type": kind,
        "source_ip": "192.0.2.10",
    }
    if kind in ("auth_failure", "auth_success"):
        item["session"] = "session-1"
    elif kind == "role_change":
        item.update(session="session-1", old_role="member", new_role="admin")
    elif kind == "token_use":
        item.update(token_id="token-1", expected_source=True)
    elif kind == "data_access":
        item.update(session="session-1", resource="report-1", classification="restricted", authorized=False, records=10)
    item.update(overrides)
    return item


def jsonl(*items):
    return "\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in items)


def findings(report):
    return [finding for incident in report["incidents"] for finding in incident["findings"]]


def rules(report):
    return [finding["rule_id"] for finding in findings(report)]


def r01_events(success_at=30):
    return [event("auth_failure", second) for second in (0, 10, 20)] + [event("auth_success", success_at)]


class IngestionTests(unittest.TestCase):
    def test_valid_event_types_and_optional_auth_sessions(self):
        items = [event(kind, index) for index, kind in enumerate(("auth_failure", "auth_success", "role_change", "token_use", "data_access"))]
        del items[0]["session"]
        del items[1]["session"]
        result = parse_jsonl(jsonl(*items))
        self.assertEqual(len(result["events"]), 5)
        self.assertEqual({e["normalized"]["type"] for e in result["events"]}, {item["type"] for item in items})

    def test_input_hash_is_of_original_utf8_bytes(self):
        raw = jsonl(event(actor="analista-á")) + "\n"
        self.assertEqual(parse_jsonl(raw)["input_sha256"], hashlib.sha256(raw.encode("utf-8")).hexdigest())

    def test_evidence_ids_are_full_sha256_and_source_lines_survive_blanks(self):
        raw = "\n" + jsonl(event()) + "\n\n" + jsonl(event(seconds=1)) + "\n"
        result = parse_jsonl(raw)
        self.assertEqual([e["source_lines"] for e in result["events"]], [[2], [4]])
        for evidence in result["events"]:
            self.assertRegex(evidence["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(evidence["evidence_id"], "ev_" + evidence["sha256"])

    def test_canonical_duplicates_retain_all_physical_source_lines(self):
        item = event()
        reversed_item = dict(reversed(list(item.items())))
        raw = json.dumps(item) + "\n\n" + json.dumps(reversed_item, indent=None, separators=(",", ":"))
        result = parse_jsonl(raw)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["source_lines"], [1, 3])
        self.assertEqual(result["duplicates"], 1)

    def test_hash_identity_ignores_json_object_order(self):
        item = event()
        first = parse_jsonl(json.dumps(item))["events"][0]
        second = parse_jsonl(json.dumps(dict(reversed(list(item.items())))))["events"][0]
        self.assertEqual(first["evidence_id"], second["evidence_id"])
        self.assertEqual(first["normalized"], second["normalized"])

    def test_events_are_sorted_by_timestamp_then_evidence_id(self):
        report = analyze(jsonl(event(seconds=3), event(seconds=1, actor="z"), event(seconds=1, actor="a")))
        actual = [(e["normalized"]["timestamp"], e["evidence_id"]) for e in report["events"]]
        self.assertEqual(actual, sorted(actual))

    def test_malformed_json_and_non_object_values_are_rejected(self):
        for raw in ('{"timestamp":', '[]', 'null', '42', '"text"'):
            with self.subTest(raw=raw), self.assertRaises(InputError):
                parse_jsonl(raw)

    def test_unknown_type_and_unknown_fields_are_rejected(self):
        for item in (event(type="password_reset"), event(extra="value"), event("token_use", session="forbidden")):
            with self.subTest(item=item), self.assertRaises(InputError):
                parse_jsonl(jsonl(item))

    def test_all_required_base_fields_are_enforced(self):
        for key in ("timestamp", "tenant", "actor", "type", "source_ip"):
            item = event()
            del item[key]
            with self.subTest(key=key), self.assertRaises(InputError):
                parse_jsonl(jsonl(item))

    def test_all_required_type_specific_fields_are_enforced(self):
        required = {
            "role_change": ("session", "old_role", "new_role"),
            "token_use": ("token_id", "expected_source"),
            "data_access": ("session", "resource", "classification", "authorized", "records"),
        }
        for kind, keys in required.items():
            for key in keys:
                item = event(kind)
                del item[key]
                with self.subTest(kind=kind, key=key), self.assertRaises(InputError):
                    parse_jsonl(jsonl(item))

    def test_base_fields_require_strings(self):
        for key in ("timestamp", "tenant", "actor", "type", "source_ip"):
            for value in (None, 1, True, [], {}):
                with self.subTest(key=key, value=value), self.assertRaises(InputError):
                    parse_jsonl(jsonl(event(**{key: value})))

    def test_boolean_fields_require_real_booleans(self):
        for kind, key in (("token_use", "expected_source"), ("data_access", "authorized")):
            for value in (0, 1, "true", "false", None):
                with self.subTest(kind=kind, value=value), self.assertRaises(InputError):
                    parse_jsonl(jsonl(event(kind, **{key: value})))

    def test_record_count_requires_bounded_integer_not_bool(self):
        for count in (-1, 1000001, 1.5, True, False, "5", None):
            with self.subTest(count=count), self.assertRaises(InputError):
                parse_jsonl(jsonl(event("data_access", records=count)))
        for count in (0, 1000000):
            with self.subTest(count=count):
                self.assertEqual(len(parse_jsonl(jsonl(event("data_access", records=count)))["events"]), 1)

    def test_role_and_classification_enums_are_strict(self):
        for key in ("old_role", "new_role"):
            for value in ("root", "Admin", None):
                with self.subTest(key=key, value=value), self.assertRaises(InputError):
                    parse_jsonl(jsonl(event("role_change", **{key: value})))
        for value in ("secret", "Restricted", None):
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_jsonl(jsonl(event("data_access", classification=value)))

    def test_timestamp_requires_rfc3339_with_timezone(self):
        for timestamp in ("2026-01-01T00:00:00", "2026-01-01", "2026-02-30T00:00:00Z", "not-a-time", "2026-01-01 00:00:00"):
            with self.subTest(timestamp=timestamp), self.assertRaises(InputError):
                parse_jsonl(jsonl(event(timestamp=timestamp)))
        for timestamp in ("2026-01-01T00:00:00.125Z", "2026-01-01T03:00:00+03:00"):
            with self.subTest(timestamp=timestamp):
                self.assertEqual(len(parse_jsonl(jsonl(event(timestamp=timestamp)))["events"]), 1)

    def test_source_ip_requires_valid_ipv4_or_ipv6(self):
        for ip in ("host.example", "999.1.1.1", "192.0.2.1:80", ""):
            with self.subTest(ip=ip), self.assertRaises(InputError):
                parse_jsonl(jsonl(event(source_ip=ip)))
        self.assertEqual(len(parse_jsonl(jsonl(event(source_ip="2001:db8::1")))["events"]), 1)

    def test_control_characters_are_rejected_inside_string_fields(self):
        for key in ("actor", "tenant", "session"):
            for control in ("\x00", "\t", "\n", "\r", "\x1f", "\x7f", "\x85"):
                with self.subTest(key=key, control=repr(control)), self.assertRaises(InputError):
                    parse_jsonl(jsonl(event(**{key: "a" + control + "b"})))

    def test_limits_are_public_and_exact(self):
        self.assertEqual((MAX_BYTES, MAX_EVENTS, MAX_LINE_BYTES), (262144, 1000, 4096))

    def test_total_byte_limit_accepts_boundary_and_rejects_overflow(self):
        raw = jsonl(event())
        raw += "\n" * (MAX_BYTES - len(raw.encode("utf-8")))
        self.assertEqual(len(raw.encode("utf-8")), MAX_BYTES)
        self.assertEqual(len(parse_jsonl(raw)["events"]), 1)
        with self.assertRaises(InputError):
            parse_jsonl(raw + "\n")

    def test_line_limit_counts_utf8_bytes_and_accepts_exact_boundary(self):
        raw = jsonl(event(actor="á"))
        raw += " " * (MAX_LINE_BYTES - len(raw.encode("utf-8")))
        self.assertEqual(len(raw.encode("utf-8")), MAX_LINE_BYTES)
        self.assertEqual(len(parse_jsonl(raw)["events"]), 1)
        self.assertLess(len(raw + " "), MAX_LINE_BYTES + 1)
        with self.assertRaises(InputError):
            parse_jsonl(raw + " ")

    def test_duplicate_json_keys_and_non_finite_numbers_are_rejected(self):
        raw = jsonl(event())
        with self.assertRaises(InputError):
            parse_jsonl(raw[:-1] + ',"actor":"replacement"}')
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_jsonl(jsonl(event("data_access", records=value)))

    def test_timestamp_rejects_out_of_range_timezone_components(self):
        for suffix in ("+00:60", "+01:99", "-01:60", "+24:00"):
            with self.subTest(suffix=suffix), self.assertRaises(InputError):
                parse_jsonl(jsonl(event(timestamp="2026-01-01T00:00:00" + suffix)))

    def test_equivalent_timezone_and_ipv6_representations_deduplicate(self):
        first = event(timestamp="2026-01-01T00:00:00Z", source_ip="2001:db8::1")
        second = event(timestamp="2026-01-01T03:00:00+03:00", source_ip="2001:0db8:0:0:0:0:0:1")
        result = parse_jsonl(jsonl(first, second))
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["source_lines"], [1, 2])
        self.assertEqual(result["duplicates"], 1)

    def test_invalid_utf8_and_non_text_input_raise_input_error(self):
        for raw in ("\ud800", b"{}", None, 12):
            with self.subTest(raw=repr(raw)), self.assertRaises(InputError):
                parse_jsonl(raw)

    def test_duplicate_event_lines_still_count_toward_input_limit(self):
        raw = "\n".join([jsonl(event())] * (MAX_EVENTS + 1))
        with self.assertRaises(InputError):
            parse_jsonl(raw)

    def test_event_count_limit_accepts_boundary_and_rejects_overflow(self):
        items = [event(seconds=i) for i in range(MAX_EVENTS)]
        self.assertEqual(len(parse_jsonl(jsonl(*items))["events"]), MAX_EVENTS)
        with self.assertRaises(InputError):
            parse_jsonl(jsonl(*items, event(seconds=MAX_EVENTS)))

    def test_report_includes_provenance_summary_and_engine(self):
        raw = jsonl(event())
        report = analyze(raw)
        for key in ("events", "incidents", "summary", "engine", "input_sha256", "duplicates"):
            self.assertIn(key, report)
        self.assertEqual(report["input_sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(report["incidents"], [])


class CorrelationTests(unittest.TestCase):
    def test_r01_requires_three_failures_and_a_later_success(self):
        self.assertEqual(rules(analyze(jsonl(*r01_events()))), ["R01"])
        self.assertEqual(rules(analyze(jsonl(*r01_events()[1:]))), [])
        self.assertEqual(rules(analyze(jsonl(*r01_events()[:-1]))), [])

    def test_r01_inclusive_five_minute_window(self):
        self.assertEqual(rules(analyze(jsonl(*r01_events(success_at=300)))), ["R01"])
        self.assertEqual(rules(analyze(jsonl(*r01_events(success_at=301)))), [])

    def test_r01_requires_success_strictly_after_failures(self):
        items = [event("auth_failure", 1, session=f"failure-{i}") for i in range(3)]
        self.assertEqual(rules(analyze(jsonl(*items, event(seconds=1)))), [])

    def test_r01_cannot_cross_tenant_actor_or_source_ip(self):
        for key, value in (("tenant", "tenant-b"), ("actor", "actor-b"), ("source_ip", "192.0.2.20")):
            items = r01_events()
            items[-1][key] = value
            with self.subTest(key=key):
                self.assertEqual(rules(analyze(jsonl(*items))), [])

    def test_r01_previous_success_resets_failure_count(self):
        items = r01_events() + [event("auth_failure", 40), event("auth_failure", 50), event(seconds=60)]
        self.assertEqual(rules(analyze(jsonl(*items))), ["R01"])

    def test_duplicates_do_not_inflate_r01_failure_threshold(self):
        failure = event("auth_failure", 0)
        self.assertEqual(rules(analyze(jsonl(failure, failure, failure, event(seconds=30)))), [])

    def test_r02_accepts_only_privilege_escalation_from_low_roles(self):
        for old_role in ("viewer", "member"):
            for new_role in ("admin", "owner"):
                with self.subTest(old_role=old_role, new_role=new_role):
                    self.assertEqual(rules(analyze(jsonl(event(), event("role_change", 1, old_role=old_role, new_role=new_role)))), ["R02"])
        for old_role, new_role in (("admin", "owner"), ("owner", "admin"), ("member", "viewer"), ("viewer", "member"), ("admin", "admin")):
            with self.subTest(old_role=old_role, new_role=new_role):
                self.assertEqual(rules(analyze(jsonl(event(), event("role_change", 1, old_role=old_role, new_role=new_role)))), [])

    def test_r02_requires_matching_tenant_actor_session_and_ip(self):
        for key, value in (("tenant", "tenant-b"), ("actor", "actor-b"), ("session", "session-2"), ("source_ip", "192.0.2.20")):
            with self.subTest(key=key):
                self.assertEqual(rules(analyze(jsonl(event(), event("role_change", 1, **{key: value})))), [])
        auth = event()
        del auth["session"]
        self.assertEqual(rules(analyze(jsonl(auth, event("role_change", 1)))), [])

    def test_r02_time_window_is_strict_start_and_inclusive_end(self):
        for second, expected in ((-1, []), (0, []), (1, ["R02"]), (600, ["R02"]), (601, [])):
            with self.subTest(second=second):
                self.assertEqual(rules(analyze(jsonl(event(), event("role_change", second)))), expected)

    def test_r03_requires_expected_use_before_unexpected_different_ip(self):
        prior = event("token_use")
        trigger = event("token_use", 1, expected_source=False, source_ip="192.0.2.20")
        self.assertEqual(rules(analyze(jsonl(prior, trigger))), ["R03"])
        self.assertEqual(rules(analyze(jsonl(trigger))), [])
        self.assertEqual(rules(analyze(jsonl(event("token_use", expected_source=False), trigger))), [])
        self.assertEqual(rules(analyze(jsonl(prior, event("token_use", 1, expected_source=False)))), [])
        self.assertEqual(rules(analyze(jsonl(prior, event("token_use", 1, source_ip="192.0.2.20")))), [])

    def test_r03_requires_matching_tenant_actor_and_token(self):
        for key, value in (("tenant", "tenant-b"), ("actor", "actor-b"), ("token_id", "token-2")):
            with self.subTest(key=key):
                trigger = event("token_use", 1, expected_source=False, source_ip="192.0.2.20", **{key: value})
                self.assertEqual(rules(analyze(jsonl(event("token_use"), trigger))), [])

    def test_r03_time_window_is_strict_start_and_inclusive_end(self):
        for second, expected in ((-1, []), (0, []), (1, ["R03"]), (600, ["R03"]), (601, [])):
            with self.subTest(second=second):
                trigger = event("token_use", second, expected_source=False, source_ip="192.0.2.20")
                self.assertEqual(rules(analyze(jsonl(event("token_use"), trigger))), expected)

    def test_r04_requires_restricted_unauthorized_nonzero_access(self):
        self.assertEqual(rules(analyze(jsonl(event(), event("data_access", 1)))), ["R04"])
        for override in ({"classification": "public"}, {"classification": "internal"}, {"authorized": True}, {"records": 0}):
            with self.subTest(override=override):
                self.assertEqual(rules(analyze(jsonl(event(), event("data_access", 1, **override)))), [])

    def test_r04_requires_matching_tenant_actor_session_and_ip(self):
        for key, value in (("tenant", "tenant-b"), ("actor", "actor-b"), ("session", "session-2"), ("source_ip", "192.0.2.20")):
            with self.subTest(key=key):
                self.assertEqual(rules(analyze(jsonl(event(), event("data_access", 1, **{key: value})))), [])
        self.assertEqual(rules(analyze(jsonl(event("data_access", 1)))), [])

    def test_r04_time_window_is_strict_start_and_inclusive_end(self):
        for second, expected in ((-1, []), (0, []), (1, ["R04"]), (600, ["R04"]), (601, [])):
            with self.subTest(second=second):
                self.assertEqual(rules(analyze(jsonl(event(), event("data_access", second)))), expected)

    def test_shuffled_input_produces_same_rule_evidence(self):
        items = r01_events() + [event("role_change", 60), event("data_access", 90)]
        forward = analyze(jsonl(*items))
        backward = analyze(jsonl(*reversed(items)))
        select = lambda report: sorted((f["rule_id"], tuple(sorted(f["evidence_ids"]))) for f in findings(report))
        self.assertEqual(select(forward), select(backward))
        self.assertEqual([e["evidence_id"] for e in forward["events"]], [e["evidence_id"] for e in backward["events"]])

    def test_timezone_offsets_are_compared_as_instants(self):
        auth = event(timestamp="2026-01-01T03:00:00+03:00")
        access = event("data_access", timestamp="2025-12-31T21:00:01-03:00")
        self.assertEqual(rules(analyze(jsonl(access, auth))), ["R04"])

    def test_all_findings_reference_existing_unique_evidence(self):
        items = r01_events() + [event("role_change", 60), event("data_access", 90), event("token_use", 100), event("token_use", 101, expected_source=False, source_ip="192.0.2.20")]
        report = analyze(jsonl(*items))
        self.assertEqual(set(rules(report)), {"R01", "R02", "R03", "R04"})
        ids = {e["evidence_id"] for e in report["events"]}
        for incident in report["incidents"]:
            self.assertEqual(set(incident["evidence_ids"]), {i for f in incident["findings"] for i in f["evidence_ids"]})
            for finding in incident["findings"]:
                for key in ("rule_id", "title", "severity", "reason", "evidence_ids", "investigation", "limitations", "attack"):
                    self.assertIn(key, finding)
                self.assertTrue(finding["evidence_ids"])
                self.assertEqual(len(finding["evidence_ids"]), len(set(finding["evidence_ids"])))
                self.assertTrue(set(finding["evidence_ids"]) <= ids)

    def test_incidents_do_not_combine_different_tenants_or_actors(self):
        items = []
        for tenant, actor in (("tenant-a", "actor-a"), ("tenant-b", "actor-a"), ("tenant-a", "actor-b")):
            items.extend([event(tenant=tenant, actor=actor), event("data_access", 1, tenant=tenant, actor=actor)])
        self.assertEqual(len(analyze(jsonl(*items))["incidents"]), 3)

    def test_incident_grouping_uses_fixed_anchor_not_transitive_chaining(self):
        items = []
        for index, second in enumerate((0, 800, 1600)):
            items.extend([event(seconds=second, session=f"session-{index}"), event("data_access", second + 1, session=f"session-{index}")])
        report = analyze(jsonl(*items))
        self.assertEqual(len(report["incidents"]), 2)
        self.assertEqual(sorted(len(i["findings"]) for i in report["incidents"]), [1, 2])

    def test_incident_anchor_uses_first_evidence_not_first_trigger(self):
        items = [event(), event("data_access", 600), event(seconds=601, session="session-2"), event("data_access", 950, session="session-2")]
        self.assertEqual(len(analyze(jsonl(*items))["incidents"]), 2)

    def test_later_finding_with_earlier_evidence_cannot_extend_full_span(self):
        items = [
            event("token_use", 0),
            event(seconds=500),
            event("data_access", 501),
            event("token_use", 600, expected_source=False, source_ip="192.0.2.20"),
            event(seconds=999, session="session-2"),
            event("data_access", 1000, session="session-2"),
        ]
        report = analyze(jsonl(*items))
        self.assertEqual(len(report["incidents"]), 2)
        self.assertEqual(sorted(len(i["findings"]) for i in report["incidents"]), [1, 2])
        by_id = {e["evidence_id"]: e for e in report["events"]}
        for incident in report["incidents"]:
            stamps = [datetime.fromisoformat(by_id[ref]["normalized"]["timestamp"].replace("Z", "+00:00")) for ref in incident["evidence_ids"]]
            self.assertLessEqual((max(stamps) - min(stamps)).total_seconds(), 900)

    def test_incident_grouping_includes_exact_fifteen_minute_boundary(self):
        for second, expected in ((900, 1), (901, 2)):
            items = [event(), event("data_access", 1), event(seconds=second - 1, session="session-2"), event("data_access", second, session="session-2")]
            with self.subTest(second=second):
                self.assertEqual(len(analyze(jsonl(*items))["incidents"]), expected)


if __name__ == "__main__":
    unittest.main()
