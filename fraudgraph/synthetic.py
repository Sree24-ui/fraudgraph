"""Explicitly synthetic scenarios for smoke tests and adversarial evaluation.

These scenarios are hand-designed fixtures, NOT evidence of real-world accuracy.
No bank, real account, real customer, or real UPI payment appears in this module.
Use the independent external evaluation for evidence beyond this generator.
"""

from __future__ import annotations

import random
import time
from typing import Any


SCENARIOS = {
    "fan_in_fan_out": "SYNTHETIC: six sources fund one mule, which pays six fresh recipients.",
    "ordinary_merchant": "SYNTHETIC benign: six customer payments and one supplier payout.",
    "legitimate_aggregator": "SYNTHETIC benign: genuine payment aggregator with the same observable shape as a mule.",
    "window_boundary": "SYNTHETIC attack: fan-in/fan-out straddles a fixed five-minute bucket boundary.",
    "slow_laundering": "SYNTHETIC attack: more than two hours separate fan-in and redistribution.",
    "distributed_hubs": "SYNTHETIC attack: four coordinating mules each have only three sources and recipients.",
    "recipient_reuse": "SYNTHETIC attack: laundering via accounts that also appear in the source set.",
    "interleaved_draining": "SYNTHETIC attack: each inflow is immediately drained before four sources accumulate.",
    "low_passthrough": "SYNTHETIC attack: a mule redistributes only 60% of the observed inflow.",
    "reverse_order": "SYNTHETIC non-matching order: all payouts precede the apparent fan-in.",
}


def generate_scenario(name: str = "fan_in_fan_out", *, now_ms: int | None = None, seed: int = 7) -> dict[str, Any]:
    """Build deterministic synthetic fixture events relative to evaluation time.

    ``ground_truth`` labels are authors' scenario intent, not observed truth.
    IDs include seed and evaluation timestamp to distinguish separate imports.
    ``expected_rule_alert`` describes the frozen rule, not scenario criminality.
    """
    if name not in SCENARIOS:
        raise ValueError(f"Unknown synthetic scenario {name!r}; choose from {', '.join(SCENARIOS)}")
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if type(now_ms) is not int or now_ms < 10_000_000:
        raise ValueError("now_ms must be integer UTC milliseconds at least 10,000,000")
    rng = random.Random(seed)
    prefix = f"syn-{name}-{now_ms}-{seed}"
    transactions: list[dict[str, Any]] = []

    def add(sender: str, receiver: str, amount: int, at: int) -> None:
        transactions.append({
            "id": f"{prefix}-{len(transactions):04d}",
            "occurred_at": at,
            "sender": sender,
            "receiver": receiver,
            "amount_paise": amount,
            "provenance": "synthetic",
        })

    hub = "synthetic:mule"
    sources = [f"synthetic:source-{i}" for i in range(6)]
    recipients = [f"synthetic:recipient-{i}" for i in range(6)]
    base = now_ms - 240_000
    amount = 10_000 + rng.randrange(0, 10_000)
    if name == "window_boundary":
        # Boundary evasion defeats fixed buckets, but trailing sliding windows
        # preserve the complete four-minute pattern at the final timestamp.
        boundary = (now_ms // 300_000) * 300_000
        if now_ms - boundary < 90_000:
            boundary -= 300_000
        base = boundary - 120_000
    if name == "slow_laundering":
        base = now_ms - 8_400_000
    if name == "distributed_hubs":
        truth = {}
        for hub_i in range(4):
            distributed_hub = f"synthetic:mule-{hub_i}"
            truth[distributed_hub] = True
            for i in range(3):
                add(f"synthetic:distributed-source-{hub_i}-{i}", distributed_hub, amount, base + i * 10_000)
                add(distributed_hub, f"synthetic:shared-settlement-{i}", amount, base + 100_000 + i * 10_000)
    elif name == "interleaved_draining":
        truth = {hub: True}
        for i in range(6):
            add(sources[i], hub, amount, base + i * 30_000)
            add(hub, recipients[i], amount, base + i * 30_000 + 1_000)
    else:
        if name in {"ordinary_merchant", "legitimate_aggregator"}:
            hub = f"synthetic:{name}"
        truth = {hub: name not in {"ordinary_merchant", "legitimate_aggregator", "reverse_order"}}
        incoming_base = base + (120_000 if name == "reverse_order" else 0)
        for i in range(6):
            add(sources[i], hub, amount, incoming_base + i * 10_000)
        outgoing_base = base if name == "reverse_order" else base + 120_000
        if name == "slow_laundering":
            outgoing_base = now_ms - 90_000
        if name == "ordinary_merchant":
            add(hub, "synthetic:supplier", amount * 6, outgoing_base)
        else:
            outgoing_recipients = sources if name == "recipient_reuse" else recipients
            outgoing_amount = amount * 60 // 100 if name == "low_passthrough" else amount
            for i in range(6):
                add(hub, outgoing_recipients[i], outgoing_amount, outgoing_base + i * 10_000)
    transactions.sort(key=lambda row: (row["occurred_at"], row["id"]))
    return {
        "name": name,
        "provenance": "synthetic",
        "description": SCENARIOS[name],
        "transactions": transactions,
        "ground_truth": truth,
        "expected_rule_alert": name in {"fan_in_fan_out", "legitimate_aggregator", "window_boundary"},
        "evaluation_time_ms": now_ms,
        "seed": seed,
        "warning": "Entirely synthetic; scenario success rates are not estimates of real UPI fraud detection accuracy.",
    }
