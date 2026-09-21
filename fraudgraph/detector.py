"""Frozen, explainable transaction-network rules; scores are not probabilities.

This module contains no trained model and makes no assertion that an alert proves
fraud. It detects a particular observable payment shape, including legitimate
businesses that share that shape. Amounts use integer paise, never float rupees.

Windows are trailing event-time intervals [now - window, now]. Four distinct
sources must arrive before a payout is counted. Equal-timestamp events do not
establish causal ordering. This intentionally conservative phase gate can miss
interleaved inflow/payout laundering. Thresholds are frozen before external-data
evaluation, and must not be described as regulatory reporting thresholds.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


DETECTOR_VERSION = "fanin-fanout-v1.0.0"


@dataclass(frozen=True)
class RuleConfig:
    windows_seconds: tuple[int, ...] = (300, 1800, 7200)
    min_sources: int = 4
    min_recipients: int = 4
    min_passthrough: float = 0.65
    max_passthrough: float = 1.35
    min_new_recipient_fraction: float = 0.8


CONFIG = RuleConfig()


def detector_config() -> dict[str, Any]:
    """Return the versioned thresholds, independently of any dataset."""
    return {"version": DETECTOR_VERSION, **asdict(CONFIG), "score_kind": "heuristic_not_probability"}


def _validated_transactions(transactions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reject malformed events; deduplicate identical retries by transaction ID."""
    seen: dict[str, dict[str, Any]] = {}
    for transaction in transactions:
        if not isinstance(transaction, dict):
            raise ValueError("Every transaction must be a dictionary")
        for field in ("id", "sender", "receiver"):
            if not isinstance(transaction.get(field), str) or not transaction[field].strip():
                raise ValueError(f"Transaction {field} must be a nonempty string")
        for field in ("occurred_at", "amount_paise"):
            if type(transaction.get(field)) is not int:
                raise ValueError(f"Transaction {field} must be an integer")
        if transaction["occurred_at"] < 0 or transaction["amount_paise"] <= 0:
            raise ValueError("Timestamp must be nonnegative and amount must be positive")
        if transaction.get("provenance") not in {"synthetic", "external_synthetic", "real"}:
            raise ValueError("Transaction provenance must be explicit")
        key = transaction["id"]
        # Ignore extra metadata when checking idempotent delivery.
        normalized = {field: transaction[field] for field in (
            "id", "occurred_at", "sender", "receiver", "amount_paise", "provenance"
        )}
        if key in seen and seen[key] != normalized:
            raise ValueError(f"Conflicting duplicate transaction ID: {key}")
        seen[key] = normalized
    return sorted(seen.values(), key=lambda row: (row["occurred_at"], row["id"]))


def detect_account(account_id: str, transactions: list[dict[str, Any]], now_ms: int) -> list[dict[str, Any]]:
    """Return explainable candidates for one account, one per matching window.

    A caller should collapse matching windows into one case per account/rule.
    This stateless interface permits deterministic replay, including events that
    arrive out of order. The caller must supply all incident events in the longest
    window and re-evaluate on late arrival. Future events and self transfers are
    ignored. Authentication, persistence, and bounded input are API concerns.

    Payouts earlier than (or equal to) the fourth distinct source arrival are
    excluded. Inflows after the latest counted payout are excluded. The remaining
    flow ratio expresses structural correlation; it does not trace ownership of
    particular funds or require a zero opening balance.
    """
    if not isinstance(account_id, str) or not account_id.strip():
        raise ValueError("Account ID must be a nonempty string")
    if type(now_ms) is not int or now_ms < 0:
        raise ValueError("now_ms must be a nonnegative integer UTC timestamp")
    rows = [row for row in _validated_transactions(transactions)
            if row["occurred_at"] <= now_ms
            and row["sender"] != row["receiver"]
            and account_id in (row["sender"], row["receiver"])]
    candidates = []
    for window_seconds in CONFIG.windows_seconds:
        window_start = now_ms - window_seconds * 1000
        window_rows = [row for row in rows if row["occurred_at"] >= window_start]
        incoming = [row for row in window_rows if row["receiver"] == account_id]
        sources_seen: set[str] = set()
        established_at = None
        for row in incoming:
            sources_seen.add(row["sender"])
            if len(sources_seen) >= CONFIG.min_sources:
                established_at = row["occurred_at"]
                break
        if established_at is None:
            continue
        outgoing = [row for row in window_rows if row["sender"] == account_id
                    and row["occurred_at"] > established_at]
        recipients = {row["receiver"] for row in outgoing}
        if len(recipients) < CONFIG.min_recipients:
            continue
        latest_outgoing_at = outgoing[-1]["occurred_at"]
        incoming = [row for row in incoming if row["occurred_at"] < latest_outgoing_at]
        sources = {row["sender"] for row in incoming}
        new_recipient_fraction = len(recipients - sources) / len(recipients)
        incoming_paise = sum(row["amount_paise"] for row in incoming)
        outgoing_paise = sum(row["amount_paise"] for row in outgoing)
        passthrough_ratio = outgoing_paise / incoming_paise
        # Integer comparisons keep the ratio boundary exact, even for large sums.
        if outgoing_paise * 100 < incoming_paise * 65 or outgoing_paise * 100 > incoming_paise * 135:
            continue
        if len(recipients - sources) * 5 < len(recipients) * 4:
            continue
        selected = sorted(incoming + outgoing, key=lambda row: (row["occurred_at"], row["id"]))
        duration_ms = selected[-1]["occurred_at"] - selected[0]["occurred_at"]
        support_bonus = min(20, (len(sources) + len(recipients) - 8) * 2)
        balance_bonus = 15 * max(0.0, 1 - abs(1 - passthrough_ratio) / 0.35)
        speed_bonus = 15 * max(0.0, 1 - duration_ms / (window_seconds * 1000))
        score = round(min(100.0, 50 + support_bonus + balance_bonus + speed_bonus), 2)
        candidates.append({
            "rule": "fan_in_fan_out",
            "detector_version": DETECTOR_VERSION,
            "window_seconds": window_seconds,
            "score": score,
            "score_kind": "heuristic_not_probability",
            "evidence": {
                "account_id": account_id,
                "transaction_ids": [row["id"] for row in selected],
                "incoming_transaction_ids": [row["id"] for row in incoming],
                "outgoing_transaction_ids": [row["id"] for row in outgoing],
                "incoming_count": len(incoming),
                "outgoing_count": len(outgoing),
                "unique_sources": len(sources),
                "unique_recipients": len(recipients),
                "source_accounts": sorted(sources),
                "recipient_accounts": sorted(recipients),
                "incoming_paise": incoming_paise,
                "outgoing_paise": outgoing_paise,
                "passthrough_ratio": round(passthrough_ratio, 8),
                "new_recipient_fraction": round(new_recipient_fraction, 8),
                "earliest_at": selected[0]["occurred_at"],
                "latest_at": selected[-1]["occurred_at"],
                "fanin_established_at": established_at,
                "first_payout_at": outgoing[0]["occurred_at"],
                "duration_seconds": duration_ms / 1000,
                "window_start": window_start,
                "window_end": now_ms,
                "provenance": sorted({row["provenance"] for row in selected}),
                "reason": (
                    f"{len(sources)} distinct sources funded the account; "
                    f"{len(recipients)} recipients received {passthrough_ratio:.1%} of observed inflow "
                    f"within a {window_seconds}-second event-time window. "
                    f"{new_recipient_fraction:.0%} of recipients were absent from the source set."
                ),
                "interpretation": "Structural suspicion requiring analyst review; not proof of crime or fund attribution.",
            },
        })
    return candidates
