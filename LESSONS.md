# Lessons from Trap #1 — Bybit Safe{Wallet} Exploit

What building this trap taught us about applying Drosera to historical exploits. Written for future Operation Flytrap traps and for anyone using this folder as a reference template.

---

## 1. The core pitch: "Don't predict attacks. Know normal."

The Bybit root cause was off-chain — a compromised Safe{Wallet} developer machine and a malicious frontend payload. No amount of on-chain heuristic detection would have anticipated *that* vector. The trap catches the attack anyway, because between block 21,895,238 and block 21,895,256 the Safe's `masterCopy` slot diverged from a governance-attested value.

The detection logic doesn't model the attacker. It models the protocol.

**Pitch this to protocols as:** four governance-attested values (`masterCopy`, `threshold`, `ownerCount`, `ownersHash`) plus 18 blocks of margin. Not "complex on-chain detection."

**For future traps:** lead every writeup with the framing that Drosera doesn't ask trap authors to anticipate attack mechanics — only to define what sanctioned state looks like. If you can't crisply define "normal" for the target, the trap will be weak regardless of how clever the detection is.

---

## 2. Detection-pattern shape: state-diff is the easy mode

Bybit fits cleanly into the **state-diff detection** shape: a single slot value diverged from a sanctioned baseline. Detection is unambiguous, the threshold is binary, and false positives only happen if the baseline is stale.

This is the easiest shape Drosera supports. The remaining shapes — statistical / anomaly detection, multi-block pattern detection, cross-protocol correlation — are progressively harder. Future Flytrap traps should deliberately probe those other shapes, because:

- They tell us where Drosera's edges are.
- They surface protocol-level friction (e.g. windowed statistics inside `pure shouldRespond` is awkward).
- "Drosera struggles with X" is a marketing deliverable, not a failure.

**For future traps:** classify candidates by detection-pattern shape before sector. A second state-diff trap is less informative than a first statistical-detection trap.

---

## 3. Fit conditions that made Bybit a clean case

Three conditions held simultaneously, which is why this trap is short, deterministic, and high-confidence:

1. **Clear on-chain state diff** — slot 0 (`masterCopy`) changed from a known address to an attacker contract.
2. **Time window between breach and loss** — 18 blocks (~3.5 minutes) between the swap and the drain. Plenty of margin for a 2/3 BLS consensus to form.
3. **Attestable baseline** — `(masterCopy, threshold, ownerCount, ownersHash)` are values governance can sanction with a single transaction.

When evaluating the next exploit candidate, score it against these three. If all three hold, the trap will be clean (like Bybit). If one fails, the trap is still worth building, but the deliverable shifts toward documenting *why* it's harder — that's the Goal-#2 finding FDR wants.

**Counter-examples to test against:**
- Frontend supply-chain attacks with instant drain → fails condition #2 (no time window).
- Oracle manipulation via legitimate-but-malicious price → fails condition #3 (no attestable "correct" price, only a statistical band).
- Reentrancy exploits → often fail condition #1 (state changes happen mid-transaction, observed state may already be "correct" by the time `collect()` runs).

---

## 4. Architectural friction worth surfacing to the Drosera team

`shouldRespond()` is `pure`. It cannot read contract state. To compare observed values against governance-attested values, we built `BaselineFeeder.sol` — a separate contract whose only job is to hold the sanctioned baseline so the trap can read it in `collect()` and embed it in every snapshot. The 26-field `Snapshot` struct carries `expectedMasterCopy`, `expectedThreshold`, `expectedOwnerCount`, `expectedOwnersHash` purely to work around the `pure` constraint.

Every future trap that needs governance-attested "normal" will pay this same tax. That's ~100 lines of feeder boilerplate plus four extra snapshot fields per attested value.

**Concrete feedback for the Drosera protocol team:** a first-class **baseline registry primitive** would:
- Remove ~100 lines of boilerplate per trap.
- Reduce per-trap audit surface.
- Let multiple traps share a single sanctioned baseline source.
- Allow `shouldRespond` to look up baselines via a sanctioned read pattern without breaking determinism.

**For future traps:** keep a running list of every place where the protocol's constraints forced a workaround. These observations are the raw material for the "what more could Drosera do if we did X" conversation.

---

## 5. Horizontal applicability is the distribution channel

Bybit's specific incident affected one exchange. But the *pattern* — a Safe{Wallet} multisig holding meaningful funds, vulnerable to implementation swap or config tampering — is present in hundreds of protocols, DAOs, and treasuries. Every Drosera-adjacent protocol has a Safe somewhere.

This trap is therefore not "the Bybit trap." It's a **deployable template for any treasury using Safe{Wallet}**:
- `BaselineFeeder` is per-Safe and governance-rotatable; redeployment is not needed.
- The responder is allowlist-driven and pausable; downstream actions are pluggable.
- The registry is bounded at 16 targets; safe to fan out to multiple emergency systems.

Toward Flytrap's 100–200 deployment target, horizontal traps like this are the most efficient lane. A bespoke trap for one protocol's specific business logic is interesting but doesn't scale.

**For future traps:** ask "is this pattern present in 1 protocol or 100?" Boring generic threats (multisig hygiene, oracle staleness, role drift, balance anomalies) are usually more distributable than novel detection of bespoke logic.

---

## 6. Sweat-the-details signal only lands if it's visible

This folder contains six contracts, 90 tests, malformed-bytes hardening via manual `calldataload` decoding, idempotent fan-out, and explicit read-status flags for every fallible read. None of that is visible to anyone who hasn't read the README.

Engineering pedigree is the antidote to the "AI slop quantity-grinding" perception Drosera's community is trying to shed. But the antidote only works if the design choices are surfaced where non-engineers can see them.

**For future traps:** every deliverable should include a **design rationale surface** — not just detection logic, but the *why* behind:
- Why this snapshot shape (Bybit: 26 fields with status flags so `MonitoringDegraded` never masquerades as `BalanceDrain`).
- Why this responder pattern (Bybit: idempotent dedupe on `keccak256(rawPayload)`, bounded registry to prevent DoS on fan-out).
- Why these gates (Bybit: absolute checks skipped if `baselineConfigured = false`; relative checks always fire).

Consider a companion writeup per trap that translates engineering decisions into community-readable language. The code already exists; the marketing surface usually doesn't, and Goal #3 (stigma removal) depends on it.

---

## How this trap scores on the six axes

| Axis | Bybit |
|---|---|
| Crisp "normal" definable | ✓ (four governance-attested values) |
| Detection-pattern shape | State-diff (easy mode) |
| State diff present | ✓ (slot 0 swap) |
| Time window | ✓ (18 blocks) |
| Attestable baseline | ✓ (single governance tx) |
| Protocol friction surfaced | ✓ (`pure shouldRespond` → BaselineFeeder pattern) |
| Horizontal applicability | High (Safe is ubiquitous) |
| Design rationale visible | Partial (README documents what; LESSONS.md documents why) |

This is the reference template. Use it as a baseline for what a Flytrap trap should clear before being called done.
