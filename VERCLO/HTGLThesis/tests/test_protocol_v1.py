from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROPOSAL_ROOT = PROJECT_ROOT.parent
PROTOCOL_ROOT = PROJECT_ROOT / "src" / "protocol"
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from protocol.state_machine import evaluate_transition  # noqa: E402
from protocol.crypto import (  # noqa: E402
    KeyRecord,
    KeyRegistry,
    body_digest,
    canonicalize,
    message_digest,
    public_key_bytes,
    sign_message,
    verify_authenticated_message,
)
from protocol.validation import AuthenticatedReplayGuard, ReplayGuard, validate_message  # noqa: E402


H = "0" * 64
T = "2026-09-04T10:00:00.000000Z"


def _body_examples() -> dict[str, dict[str, object]]:
    ids = ["OBLIGATION:001"]
    return {
        "CASE_SUBMIT": {"case_id":"CASE:001","request_ref":"REQUEST:001","root_asset_refs":["ASSET:001"],"policy_profile_ref":"POLICY:001","authorization_ref":"AUTH:001","lineage_snapshot_time":T,"requested_deadline":"2026-09-05T10:00:00.000000Z"},
        "CASE_ACCEPT": {"case_id":"CASE:001","request_ref":"REQUEST:001","policy_profile_ref":"POLICY:001","accepted_at":T,"evaluation_deadline":"2026-09-05T10:00:00.000000Z","acceptance_commitment":H},
        "SCOPE_DECLARE": {"case_id":"CASE:001","scope_version":1,"relationship_refs":["REL:001"],"replica_refs":["REPLICA:001"],"predecessor_scope_commitment":None},
        "SCOPE_COMMIT": {"case_id":"CASE:001","scope_version":1,"obligation_version":1,"scope_commitment":H,"obligation_commitment":H,"no_applicable_obligations":False},
        "LINEAGE_DISCLOSE": {"case_id":"CASE:001","relationship_refs":["REL:002"],"disclosure_evidence_refs":["EVIDENCE:001"],"disclosed_at":T},
        "OBLIGATION_ASSIGN": {"case_id":"CASE:001","scope_version":1,"obligation_version":1,"obligations":[{"obligation_id":"OBLIGATION:001","asset_id":"ASSET:001","replica_id":"REPLICA:001","repository_id":"REPOSITORY:001","custodian_principal_id":"PRINCIPAL:CUSTODIAN","deadline":"2026-09-05T10:00:00.000000Z","minimum_grade":"E2","permitted_dispositions":["ERASED"]}]},
        "ERASURE_COMMAND": {"case_id":"CASE:001","obligation_refs":ids,"command_commitment":H,"issued_at":T},
        "TERMINAL_RECEIPT": {"case_id":"CASE:001","obligation_id":"OBLIGATION:001","asset_id":"ASSET:001","replica_id":"REPLICA:001","repository_id":"REPOSITORY:001","disposition":"ERASED","event_time":T,"receipt_type":"deletion_acknowledgement","payload_commitment":H,"provenance_refs":["COMMAND:001"]},
        "EXCEPTION_ASSERT": {"case_id":"CASE:001","exception_id":"EXCEPTION:001","obligation_refs":ids,"basis_commitment":H,"effective_at":T,"expires_at":"2027-09-04T10:00:00.000000Z","evidence_refs":["EVIDENCE:001"]},
        "EVIDENCE_ANCHOR": {"case_id":"CASE:001","anchor_id":"ANCHOR:001","evidence_refs":["EVIDENCE:001"],"anchor_time":T,"log_sequence":1,"root_commitment":H},
        "VIEW_COMMIT": {"case_id":"CASE:001","scope_version":1,"projection_profile_id":"PROFILE:AUDITOR","view_commitment":H,"record_count":3},
        "CHALLENGE_OPEN": {"case_id":"CASE:001","challenge_id":"CHALLENGE:001","challenge_kind":"EVIDENCE","target_ref":"EVIDENCE:001","grounds_commitment":H,"opened_at":T},
        "CHALLENGE_RESOLVE": {"case_id":"CASE:001","challenge_id":"CHALLENGE:001","resolution":"UPHELD","evidence_refs":["EVIDENCE:002"],"reason_codes":["INVALID_AUTHENTICATOR"],"resolved_at":T},
        "CLOSURE_QUERY": {"case_id":"CASE:001","query_id":"QUERY:CLOSURE","evaluation_time":T,"scope_version":1,"obligation_version":1},
        "CLOSURE_DECISION": {"case_id":"CASE:001","query_id":"QUERY:CLOSURE","outcome":"CLOSED","evaluation_time":T,"scope_version":1,"obligation_version":1,"policy_profile_ref":"POLICY:001","considered_obligation_refs":ids,"reason_codes":["ALL_OBLIGATIONS_RESOLVED"],"decision_commitment":H},
        "EVIDENCE_VALIDATION": {"case_id":"CASE:001","evidence_id":"EVIDENCE:001","obligation_id":"OBLIGATION:001","status":"GRADED","grade":"E3","rejection_code":None,"verified_capabilities":["record","assertion","authentication","binding","integrity","ordering"],"validated_at":T},
        "DISPUTE_OPEN": {"case_id":"CASE:001","dispute_id":"DISPUTE:001","conflict_class":"DISPOSITION","evidence_refs":["EVIDENCE:001","EVIDENCE:002"],"challenge_refs":[],"opened_at":T},
        "DISPUTE_RESOLVE": {"case_id":"CASE:001","dispute_id":"DISPUTE:001","accepted_evidence_refs":["EVIDENCE:001"],"rejected_evidence_refs":["EVIDENCE:002"],"reason_codes":["INVALID_AUTHENTICATOR"],"resolved_at":T},
        "EXCEPTION_DECISION": {"case_id":"CASE:001","exception_id":"EXCEPTION:001","decision":"ACCEPTED","reason_codes":["VALID_EXCEPTION_PRESENT"],"decided_at":T},
        "AUDIT_QUERY": {"case_id":"CASE:001","query_id":"QUERY:AUDIT","as_of":T,"selectors":["CASE_BASELINE","EVIDENCE"],"projection_profile_id":"PROFILE:AUDITOR"},
        "AUDIT_RESPONSE": {"case_id":"CASE:001","query_id":"QUERY:AUDIT","projection_profile_id":"PROFILE:AUDITOR","record_refs":["RECORD:001"],"response_commitment":H,"responded_at":T,"next_cursor":None}
    }


def _message(message_type: str, body: dict[str, object], role: str) -> dict[str, object]:
    return {
        "schema_id":"https://pae.local/schema/cpae-message/v1",
        "protocol_version":"C-PAE-1.0.0",
        "model_version":"PAE-FECM-v1.0.0",
        "message_id":f"MSG:{message_type}",
        "message_type":message_type,
        "sender":{"principal_id":"PRINCIPAL:SENDER","organization_id":"ORG:SENDER","role":role,"key_id":"KEY:SENDER"},
        "recipients":["PRINCIPAL:RECIPIENT"],
        "sequence_number":0,
        "nonce":"a" * 32,
        "claimed_event_time":T,
        "emitted_at":T,
        "received_at":T,
        "body_digest":H,
        "previous_message_digest":None,
        "signature":{"algorithm":"Ed25519","canonicalization":"RFC8785-JCS","domain":"C-PAE-MESSAGE-v1","value":"A" * 32},
        "delivery_state":"DELIVERED",
        "body":body
    }


class CPaEProtocolV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads((PROTOCOL_ROOT / "cpae_message_v1.schema.json").read_text())
        cls.error_schema = json.loads((PROTOCOL_ROOT / "cpae_error_v1.schema.json").read_text())
        cls.machine = json.loads((PROTOCOL_ROOT / "cpae_state_machine_v1.json").read_text())
        cls.catalog = json.loads((PROTOCOL_ROOT / "cpae_message_catalog_v1.json").read_text())
        cls.rejections = json.loads((PROTOCOL_ROOT / "cpae_rejection_codes_v1.json").read_text())
        cls.cases = json.loads((PROJECT_ROOT / "tests" / "protocol_conformance_cases_v1.json").read_text())

    def test_schemas_are_valid_and_every_message_body_validates(self) -> None:
        Draft202012Validator.check_schema(self.schema)
        Draft202012Validator.check_schema(self.error_schema)
        catalog = {row["message_type"]: row for row in self.catalog["messages"]}
        examples = _body_examples()
        self.assertEqual(set(self.schema["properties"]["message_type"]["enum"]), set(examples))
        for message_type, body in examples.items():
            validate_message(_message(message_type, body, catalog[message_type]["sender_roles"][0]))

    def test_message_catalog_has_no_undefined_roles_messages_or_paths(self) -> None:
        messages = self.schema["properties"]["message_type"]["enum"]
        schema_roles = set(self.schema["$defs"]["Sender"]["properties"]["role"]["enum"])
        transitions = {row["id"] for row in self.machine["transitions"]}
        body_defs = set(self.schema["$defs"])
        self.assertEqual(set(messages), {row["message_type"] for row in self.catalog["messages"]})
        for row in self.catalog["messages"]:
            self.assertTrue(set(row["sender_roles"]) <= schema_roles)
            self.assertTrue(set(row["recipient_roles"]) <= schema_roles)
            self.assertTrue(set(row["protocol_transitions"]) <= transitions)
            self.assertIn(row["body_definition"], body_defs)

    def test_every_formal_transition_has_a_protocol_path(self) -> None:
        expected = {f"TR-{index:02d}" for index in range(1, 22)}
        covered = {item for row in self.machine["transitions"] for item in row["formal_transition_ids"]}
        self.assertEqual(expected, covered)

    def test_every_transition_and_guard_has_an_explicit_rejection(self) -> None:
        known = {row["code"] for row in self.rejections["rejection_codes"]}
        known.update({"UNAUTHORIZED_ROLE", "INVALID_STATE_TRANSITION", "UNKNOWN_TRANSITION"})
        for row in self.machine["transitions"]:
            self.assertEqual(set(row["required_facts"]), set(row["guard_failures"]))
            facts = {name: True for name in row["required_facts"]}
            accepted = evaluate_transition(row["id"], phase=row["from_phases"][0], actor_role=row["actor_roles"][0], facts=facts, catalog=self.machine)
            self.assertTrue(accepted.accepted)
            for fact, code in row["guard_failures"].items():
                altered = dict(facts)
                altered[fact] = False
                rejected = evaluate_transition(row["id"], phase=row["from_phases"][0], actor_role=row["actor_roles"][0], facts=altered, catalog=self.machine)
                self.assertFalse(rejected.accepted)
                self.assertEqual(code, rejected.rejection_code)
                self.assertEqual(rejected.prior_phase, rejected.next_phase)
                self.assertIn(code, known)

    def test_named_invalid_cases_return_exact_codes_without_state_change(self) -> None:
        transitions = {row["id"]: row for row in self.machine["transitions"]}
        for case in self.cases["invalid_transitions"]:
            row = transitions[case["transition_id"]]
            facts = {name: True for name in row["required_facts"]}
            if case["false_fact"] is not None:
                facts[case["false_fact"]] = False
            result = evaluate_transition(case["transition_id"], phase=case["phase"], actor_role=case["actor_role"], facts=facts, catalog=self.machine)
            self.assertFalse(result.accepted, case["case_id"])
            self.assertEqual(case["expected_code"], result.rejection_code, case["case_id"])
            self.assertEqual(result.prior_phase, result.next_phase, case["case_id"])

    def test_four_normative_traces_reach_decided(self) -> None:
        transitions = {row["id"]: row for row in self.machine["transitions"]}
        for trace in self.cases["valid_traces"]:
            phase = "NONE"
            for transition_id in trace["transitions"]:
                row = transitions[transition_id]
                result = evaluate_transition(transition_id, phase=phase, actor_role=row["actor_roles"][0], facts={name: True for name in row["required_facts"]}, catalog=self.machine)
                self.assertTrue(result.accepted, f"{trace['trace_id']} at {transition_id}")
                phase = result.next_phase
            self.assertEqual(trace["expected_final_phase"], phase)

    def test_replay_guard_is_idempotent_and_fail_closed(self) -> None:
        catalog = {row["message_type"]: row for row in self.catalog["messages"]}
        first = _message("CASE_SUBMIT", _body_examples()["CASE_SUBMIT"], catalog["CASE_SUBMIT"]["sender_roles"][0])
        guard = ReplayGuard()
        digest = "1" * 64
        self.assertEqual("ACCEPTED", guard.accept(first, digest))
        self.assertEqual("IDEMPOTENT_REPLAY", guard.accept(first, digest))
        changed = copy.deepcopy(first)
        changed["body"]["request_ref"] = "REQUEST:DIFFERENT"
        with self.assertRaisesRegex(ValueError, "MESSAGE_ID_REUSE"):
            guard.accept(changed, "2" * 64)

    def test_rfc8785_profile_is_deterministic_and_rejects_ambiguous_numbers(self) -> None:
        value = {"z": 3, "a": [True, None, "€"], "\U0001f600": 2, "\ue000": 1}
        self.assertEqual(
            canonicalize(value),
            '{"a":[true,null,"€"],"z":3,"😀":2,"":1}'.encode(),
        )
        self.assertEqual(body_digest({"b": 2, "a": 1}), body_digest({"a": 1, "b": 2}))
        with self.assertRaisesRegex(ValueError, "MALFORMED_CANONICAL_PAYLOAD"):
            canonicalize({"number": 1.0})
        with self.assertRaisesRegex(ValueError, "MALFORMED_CANONICAL_PAYLOAD"):
            canonicalize({"number": 1 << 60})

    def test_authenticated_profile_verifies_all_admitted_algorithms(self) -> None:
        algorithms = (
            ("Ed25519", ed25519.Ed25519PrivateKey.generate()),
            ("ECDSA-P256-SHA256", ec.generate_private_key(ec.SECP256R1())),
            ("RSA-PSS-SHA256", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        )
        event = datetime.fromisoformat(T.replace("Z", "+00:00"))
        for algorithm, private_key in algorithms:
            with self.subTest(algorithm=algorithm):
                message = _message("CASE_SUBMIT", _body_examples()["CASE_SUBMIT"], "REQUESTER")
                message["sender"]["key_id"] = f"KEY:{algorithm.replace('-', '_').upper()}"
                message["signature"]["algorithm"] = algorithm
                signed = sign_message(message, private_key)
                registry = KeyRegistry([
                    KeyRecord(
                        key_id=signed["sender"]["key_id"],
                        principal_id="PRINCIPAL:SENDER",
                        organization_id="ORG:SENDER",
                        roles=frozenset({"REQUESTER"}),
                        algorithm=algorithm,
                        public_key=public_key_bytes(private_key.public_key()),
                        valid_from=event - timedelta(days=1),
                        valid_until=event + timedelta(days=1),
                    )
                ])
                self.assertEqual(message_digest(signed), verify_authenticated_message(signed, registry))

    def test_authenticated_profile_detects_body_envelope_and_key_tampering(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        event = datetime.fromisoformat(T.replace("Z", "+00:00"))
        message = _message("CASE_SUBMIT", _body_examples()["CASE_SUBMIT"], "REQUESTER")
        signed = sign_message(message, private_key)
        record = KeyRecord(
            key_id="KEY:SENDER",
            principal_id="PRINCIPAL:SENDER",
            organization_id="ORG:SENDER",
            roles=frozenset({"REQUESTER"}),
            algorithm="Ed25519",
            public_key=public_key_bytes(private_key.public_key()),
            valid_from=event - timedelta(days=1),
            valid_until=event + timedelta(days=1),
        )
        registry = KeyRegistry([record])

        body_tampered = copy.deepcopy(signed)
        body_tampered["body"]["request_ref"] = "REQUEST:TAMPERED"
        with self.assertRaisesRegex(ValueError, "BODY_DIGEST_MISMATCH"):
            verify_authenticated_message(body_tampered, registry)

        envelope_tampered = copy.deepcopy(signed)
        envelope_tampered["recipients"] = ["PRINCIPAL:ATTACKER"]
        with self.assertRaisesRegex(ValueError, "INVALID_SIGNATURE"):
            verify_authenticated_message(envelope_tampered, registry)

        expired = KeyRegistry([KeyRecord(
            **{**record.__dict__, "valid_from": event - timedelta(days=2), "valid_until": event}
        )])
        with self.assertRaisesRegex(ValueError, "CREDENTIAL_INVALID_AT_EVENT"):
            verify_authenticated_message(signed, expired)

        revoked = KeyRegistry([KeyRecord(
            **{**record.__dict__, "revoked_at": event - timedelta(seconds=1)}
        )])
        with self.assertRaisesRegex(ValueError, "CREDENTIAL_INVALID_AT_EVENT"):
            verify_authenticated_message(signed, revoked)

    def test_authenticated_replay_guard_binds_verification_and_continuity(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        event = datetime.fromisoformat(T.replace("Z", "+00:00"))
        registry = KeyRegistry([KeyRecord(
            key_id="KEY:SENDER", principal_id="PRINCIPAL:SENDER",
            organization_id="ORG:SENDER", roles=frozenset({"REQUESTER"}),
            algorithm="Ed25519", public_key=public_key_bytes(private_key.public_key()),
            valid_from=event - timedelta(days=1), valid_until=event + timedelta(days=1),
        )])
        guard = AuthenticatedReplayGuard(registry)
        first = sign_message(_message("CASE_SUBMIT", _body_examples()["CASE_SUBMIT"], "REQUESTER"), private_key)
        self.assertEqual("ACCEPTED", guard.accept(first))
        self.assertEqual("IDEMPOTENT_REPLAY", guard.accept(first))
        observed_again = copy.deepcopy(first)
        observed_again["received_at"] = "2026-09-04T10:00:01.000000Z"
        observed_again["delivery_state"] = "IN_FLIGHT"
        self.assertEqual(message_digest(first), message_digest(observed_again))
        self.assertEqual("IDEMPOTENT_REPLAY", guard.accept(observed_again))

        second = _message("CASE_SUBMIT", _body_examples()["CASE_SUBMIT"], "REQUESTER")
        second["message_id"] = "MSG:CASE_SUBMIT:2"
        second["nonce"] = "b" * 32
        second["sequence_number"] = 1
        second["previous_message_digest"] = message_digest(first)
        second = sign_message(second, private_key)
        self.assertEqual("ACCEPTED", guard.accept(second))

    def test_safety_and_conditional_progress_structure(self) -> None:
        transitions = self.machine["transitions"]
        deciding = [row for row in transitions if row["to_phase"] == "DECIDED"]
        self.assertEqual(["CPAE-TR-22"], [row["id"] for row in deciding])
        self.assertEqual("CLOSURE_DECISION", deciding[0]["message_type"])

        # A later authenticated lineage disclosure must invalidate finality and
        # reopen the case at SCOPED, as required by the protocol prose.
        reopen = next(row for row in transitions if row["id"] == "CPAE-TR-13")
        result = evaluate_transition(
            reopen["id"], phase="DECIDED", actor_role="AUDITOR",
            facts={fact: True for fact in reopen["required_facts"]}, catalog=self.machine,
        )
        self.assertTrue(result.accepted)
        self.assertEqual("SCOPED", result.next_phase)

        # Under fair delivery and true guards there is a finite route from a new
        # case to DECIDED; this is the catalogue-level conditional liveness check.
        edges: dict[str, set[str]] = {}
        for row in transitions:
            for phase in row["from_phases"]:
                target = phase if row["to_phase"] == "$SAME" else row["to_phase"]
                edges.setdefault(phase, set()).add(target)
        frontier, visited = ["NONE"], set()
        while frontier:
            phase = frontier.pop()
            if phase in visited:
                continue
            visited.add(phase)
            frontier.extend(edges.get(phase, set()) - visited)
        self.assertIn("DECIDED", visited)


    def test_error_record_schema_and_codes_are_closed(self) -> None:
        record = {"schema_id":"https://pae.local/schema/cpae-error/v1","protocol_version":"C-PAE-1.0.0","error_id":"ERROR:001","offending_message_id":"MSG:001","case_id":"CASE:001","rejection_code":"INVALID_SIGNATURE","rejected_at":T,"retryable":False,"state_unchanged":True,"details_commitment":H}
        Draft202012Validator(self.error_schema, format_checker=FormatChecker()).validate(record)
        codes = [row["code"] for row in self.rejections["rejection_codes"]]
        self.assertEqual(len(codes), len(set(codes)))
        self.assertIn(record["rejection_code"], codes)


if __name__ == "__main__":
    unittest.main()
