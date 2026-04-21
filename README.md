# Bybit Safe{Wallet} Exploit Trap

**Operation Flytrap PoC — Bybit $1.46B Hack (February 21, 2025)**

Production-grade Drosera trap demonstrating how the protocol would have detected and contained the largest cryptocurrency theft in history. Incidents carry a structured payload, `shouldRespond()` validates strict sample ordering, every fallible read (Safe reads **and** token balance reads) exposes a status flag, baselines are rotated on-chain through a governance-owned feeder, and the responder is idempotent and fans out to a bounded, governance-owned registry of emergency-action targets.

## The Attack

On February 21, 2025, the Bybit exchange suffered the largest cryptocurrency theft in history. The Lazarus Group stole **$1.46 billion** in ETH and liquid staking tokens from Bybit's cold wallet — a Safe{Wallet} multisig.

### How It Happened

1. **Feb 4**: Attacker compromised a Safe{Wallet} developer's macOS machine via social engineering.
2. **Feb 18**: Attacker deployed two malicious contracts on Ethereum.
3. **Feb 21, Block 21,895,238** — *masterCopy swap*:
   - Malicious JS in Safe's frontend showed Bybit signers a legitimate-looking transfer.
   - The real payload was a `delegatecall` (operation=1) to the attacker's contract.
   - That contract's `transfer(address,uint256)` wrote its first argument into **storage slot 0**, overwriting the Safe proxy's `masterCopy`.
4. **Block 21,895,256** — *drain*: with `masterCopy` pointing to a malicious implementation, the attacker called backdoor functions and swept all funds.

**18 blocks separate the swap from the drain** — ample time for a Drosera consensus to form and submit a response.

### Stolen Assets

401,346 ETH  ·  90,375 stETH  ·  8,000 mETH  ·  15,000 cmETH

### Key Addresses

| Role | Address |
|---|---|
| Victim (Bybit Cold Wallet) | `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4` |
| Attacker EOA | `0x0fa09c3a328792253f8dee7116848723b72a6d2e` |
| Malicious Implementation | `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516` |
| Storage Manipulator | `0x96221423681A6d52E184D440a8eFCEbB105C7242` |
| Exploit TX | `0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882` |

## Threat Model

| Aspect | Detail |
|---|---|
| **Target** | Safe{Wallet} multisig proxy contracts holding protocol treasuries |
| **Attack** | Proxy implementation (masterCopy) swap via delegatecall, enabling backdoor drain functions |
| **Scope** | Implementation compromise, configuration tampering, balance anomalies, and loss of monitoring visibility |
| **Not in scope** | Social engineering of signers, frontend supply-chain attacks (Bybit's root cause), off-chain key compromise without any on-chain state change |

## Architecture

The system is split into six contracts:

```
src/
  interfaces/ITrap.sol            Local Drosera trap interface
  BybitSafeTrapV2.sol             Trap: collect + shouldRespond (pure)
  BaselineFeeder.sol              Governance-owned per-Safe baseline config
  SafeGuardResponderV2.sol        Responder: idempotent, allowlisted, pausable
  SafeGuardianRegistry.sol        Governance-owned bounded allowlist of emergency targets
  mocks/MockGuardianTarget.sol    Downstream pause target used by tests
```

Data flow:

```
governance → feeder.setBaseline(safe, masterCopy, threshold, owners, ownersHash)
operator → trap.collect()                       (every block, view — reads feeder)
operator → trap.shouldRespond(data[])           (pure, 10-sample window)
           ↓ returns abi.encode(IncidentPayload)
consensus → responder.handleIncident(payload)   (idempotent, dedupes by keccak256)
           ↓ fans out to every approved target (bounded ≤ 16)
registry → target.emergencyPause(payload)       (try/catch per target)
```

### BaselineFeeder

`pure` `shouldRespond()` cannot read contract state, so the trap reads the governance-approved `(masterCopy, threshold, ownerCount, ownersHash)` baseline at `collect()` time from the feeder and embeds it in every snapshot. `shouldRespond()` consumes it from the sample bytes.

Rotating the baseline therefore happens on-chain — `feeder.setBaseline(...)` behind the governance multisig/timelock — with no trap redeploy. If the feeder read fails or the Safe is not yet configured, `baselineConfigured = false` and absolute checks (MasterCopyChanged / ConfigChanged-absolute) are skipped; relative checks and all non-baseline triggers still fire.

### Snapshot (25 fields, 800 bytes encoded)

`collect()` emits a snapshot bound to both a block and a Safe. Every fallible read returns a status flag so `shouldRespond()` can tell "loss of visibility" from "legitimately zero":

| Group | Fields |
|---|---|
| Binding | `safeProxy`, `blockNumber` |
| Read status | `implementationValid`, `masterCopyReadOk`, `guardReadOk`, `modulesReadComplete`, `balancesReadOk`, `baselineConfigured` |
| Safe core | `masterCopy`, `threshold`, `ownerCount`, `ownersHash`, `nonce` |
| Modules & guard | `moduleCount`, `modulesHash`, `guard` |
| Expected baseline | `expectedMasterCopy`, `expectedThreshold`, `expectedOwnerCount`, `expectedOwnersHash` |
| Balances | `ethBalance`, `stethBalance`, `methBalance`, `cmethBalance`, `aggregateBalance` |

`aggregateBalance` only sums tokens whose reads succeeded; a failed token read sets `balancesReadOk = false` rather than silently contributing zero.

### Structured Incident Payload

Every trigger returns an `IncidentPayload` the responder consumes as a single `bytes` arg:

```solidity
struct IncidentPayload {
    ThreatType threatType;          // enum, see below
    address safeProxy;
    uint256 currentBlockNumber;
    uint256 previousBlockNumber;
    bytes details;                  // threat-specific extras
}
```

Matching signature: `handleIncident(bytes)`.

## Detection Vectors

`shouldRespond()` evaluates in strict priority order and short-circuits on the first hit. It also rejects the window if samples are non-contiguous, out of order, or refer to a different `safeProxy`.

| # | ThreatType | Severity | What fires it |
|---|---|---|---|
| 1 | `MonitoringDegraded` | CRITICAL | Any of the paginated-complete / masterCopy-read / guard-read / balances-read flags is false. Loss of visibility — on Safe state **or** token balances — is itself treated as actionable, so a failed token read cannot masquerade as `BalanceDrain`. |
| 2 | `ImplementationCompromised` | CRITICAL | `getThreshold()` / `getOwners()` / `nonce()` reverted or returned absurd values. This is the **primary Bybit signal** — the malicious implementation did not implement the Safe ABI. |
| 3 | `MasterCopyChanged` | CRITICAL | Slot-0 read != feeder's `expectedMasterCopy`. Catches the class of attacks where the swapped-in implementation still serves Safe ABI but adds backdoor logic. *(Absolute check — gated on `baselineConfigured`.)* |
| 4 | `ConfigChanged` | CRITICAL | `threshold` / `ownerCount` / `ownersHash` != feeder's expected baseline. *(Absolute check — gated on `baselineConfigured`.)* |
| 5 | `GuardChanged` | CRITICAL | Guard storage slot differs from the previous snapshot. *(Relative check.)* |
| 6 | `ModulesChanged` | CRITICAL | Module count or hash differs from the previous snapshot. Suppressed when the previous read was incomplete — a truncated read must never look like modules vanished. *(Relative check.)* |
| 7 | `ConfigChanged` *(relative)* | CRITICAL | Threshold/owners drift block-over-block even without an absolute baseline. |
| 8 | `BalanceDrain` | CRITICAL | Aggregate balance dropped ≥ 5 % in a single block. Suppressed when the previous sample's balance read was degraded — a recovering RPC must never look like a drain. |
| 9 | `GradualDrain` | WARNING | Cumulative drop newest vs. oldest ≥ 15 % across the full 10-block window. Suppressed when the oldest sample's balance read was degraded. |
| 10 | `NonceJump` | WARNING | Nonce incremented by more than 5 in a single block. |

Absolute checks (vs known-good baseline) **and** relative checks (vs previous snapshot) are both present. Relative alone misses attacks that were already in place at deploy time; absolute alone misses unanticipated drift.

## Responder

`SafeGuardResponderV2` consumes a single abi-encoded `IncidentPayload`. It is:

- **Allowlisted** — a configurable `relayer` plus a mapping of additional `allowedCallers`, since the real Drosera executor may vary by network.
- **Idempotent** — the payload's `keccak256` is the incident ID; retries are no-ops.
- **Globally pausable** — admin can kill-switch the responder during a false-positive storm.
- **Bounded fan-out** — reads `SafeGuardianRegistry.getTargets()` and calls `emergencyPause(payload)` on each approved target via `try/catch`, so one misbehaving target cannot block the others. The registry caps total targets at `MAX_TARGETS = 16`, bounding fan-out gas.

`SafeGuardianRegistry` is a standalone contract owned by governance; approved targets are added/rotated without redeploying the responder. A target is inserted into `targets[]` at most once (tracked via an internal `_seen` flag), so a revoke-then-re-approve cycle never produces duplicate on-chain calls.

### Malformed-bytes safety

`shouldRespond()` parses snapshot bytes with a manual length check and per-slot `calldataload`, not `abi.decode`. Malformed input (wrong length, garbage payload) returns `(false, "")` gracefully rather than reverting the operator's consensus call. Empty previous samples are treated as a benign transient and simply skip relative checks.

## Running the Tests

```bash
bun install
forge build
forge test --match-path 'test/BybitSafeTrapV2.t.sol' -vv
```

Fork tests require an Ethereum archive RPC; the default is `https://eth.drpc.org` via `foundry.toml`.

### Test Inventory (56/56 passing)

**Trap — synthetic windows (29 tests)**

| Bucket | Tests |
|---|---|
| Normal | `test_NoTrigger_HealthyWindow` |
| Input guards | `test_NoTrigger_EmptyData`, `test_NoTrigger_SingleSample`, `test_NoTrigger_OversizedWindow`, `test_NoTrigger_NonContiguousBlocks`, `test_NoTrigger_ReorderedBlocks`, `test_NoTrigger_ZeroSafeProxy`, `test_NoTrigger_MismatchedSafeProxy`, `test_NoTrigger_MalformedBytes_WrongLength`, `test_NoTrigger_MalformedBytes_EmptyPrevious` |
| Triggers | one per ThreatType: `MonitoringDegraded` (master-copy read, balances read), `ImplementationCompromised`, `MasterCopyChanged`, `GuardChanged`, `ModulesChanged`, `BalanceDrain`, `GradualDrain`, `NonceJump` |
| Absolute baseline | `test_Trigger_ConfigChanged_AbsoluteThreshold`, `test_Trigger_ConfigChanged_AbsoluteOwnerCount`, `test_NoTrigger_BaselineUnconfigured_NoFalseAbsolute` |
| Relative | `test_Trigger_ConfigChanged_RelativeOwnersHash`, `test_NoTrigger_ModulesChanged_PreviousIncompleteRead` |
| Balance-read status | `test_NoTrigger_BalanceDrain_PreviousBalancesDegraded` |
| Boundaries | `test_NoTrigger_BalanceDrain_JustBelowThreshold`, `test_NoTrigger_NonceJump_AtThreshold` |
| Priority | `test_Priority_MonitoringDegradedBeatsImplementation`, `test_Priority_ImplementationBeatsMasterCopy` |

**Trap — mainnet fork (3 tests)**

| Test | What it proves |
|---|---|
| `test_Fork_PreExploit_CollectHealthy` | At block 21,895,237 `collect()` returns `implementationValid = true`, threshold = 3, > 400k ETH, correct `safeProxy` binding |
| `test_Fork_AtSwap_ImplementationInvalid` | At block 21,895,238 `implementationValid = false` and slot 0 is proven overwritten via `vm.load` |
| `test_Fork_AtSwap_TrapFiresImplementationCompromised` | `shouldRespond()` fires with `ImplementationCompromised`, correct block binding, correct `safeProxy` |

**BaselineFeeder (6 tests)**

| Area | Tests |
|---|---|
| Auth | `test_Set_OnlyOwner`, `test_SetOwner_OnlyOwner` |
| Validation | `test_Set_RejectsInvalid` |
| Read path | `test_Set_AndRead`, `test_UnsetBaseline_ReturnsUnconfigured`, `test_ClearBaseline` |

**Responder + Registry + Fan-out (18 tests)**

| Area | Tests |
|---|---|
| Auth | `test_Auth_Relayer_CanHandle`, `test_Auth_AllowedCaller_CanHandle`, `test_Auth_Unauthorized_Reverts`, `test_Auth_OnlyAdminCanSetAllowed` |
| Idempotency | `test_Idempotent_DoubleCallDoesNotDoubleExecute`, `test_Idempotent_DifferentPayloadsProduceSeparateIncidents` |
| Validation | `test_Reject_InvalidThreatType`, `test_Reject_ZeroSafeProxy`, `test_Reject_BadBlockOrdering` |
| Global pause | `test_GlobalPause_BlocksHandle` |
| Fan-out | `test_FanOut_CallsAllApprovedTargets`, `test_FanOut_RevokedTargetIsSkipped`, `test_FanOut_RevertingTargetDoesNotBlockOthers`, `test_FanOut_NoDuplicateCallAfterRevokeReapprove` |
| Registry | `test_Registry_OnlyOwnerCanSetTarget`, `test_Registry_DuplicateApprovalDoesNotDuplicateEntry`, `test_Registry_RevokeAndReapproveDoesNotDuplicate`, `test_Registry_MaxTargetsBound` |

### Fork-test caveat

Foundry forks return empty bytes from Safe's `getStorageAt` — a known environmental limitation, not a trap defect. The trap correctly flags this as `MonitoringDegraded`. The fork tests normalize the read flags before exercising the `ImplementationCompromised` path so the assertion chain proves the real Bybit signal. Real operator RPCs are not affected.

## Deployment

Deployment is a four-contract sequence. Every `initialOwner` / `admin` / `relayer` below **must** be a governance multisig + timelock in production — an EOA makes the contracts governance-*compatible*, not governance-*managed*.

```bash
# 1. BaselineFeeder — governance sets the per-Safe expected config
forge create src/BaselineFeeder.sol:BaselineFeeder \
  --constructor-args <GOVERNANCE_MULTISIG>

# 2. SafeGuardianRegistry — governance-owned bounded allowlist
forge create src/SafeGuardianRegistry.sol:SafeGuardianRegistry \
  --constructor-args <GOVERNANCE_MULTISIG>

# 3. BybitSafeTrapV2 — immutables: Safe proxy, feeder, and the three LST addresses
forge create src/BybitSafeTrapV2.sol:BybitSafeTrapV2 \
  --constructor-args \
    0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4 \
    <BASELINE_FEEDER> \
    0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84 \
    0xd5F7838F5C461fefF7FE49ea5ebaF7728bB0ADfa \
    0xe3C063B1BEe9de02eb28352b55D49D85514C67FF

# 4. SafeGuardResponderV2 — (admin, relayer, registry)
forge create src/SafeGuardResponderV2.sol:SafeGuardResponderV2 \
  --constructor-args \
    <GOVERNANCE_MULTISIG> \
    0x01C344b8406c3237a6b9dbd06ef2832142866d87 \
    <SAFE_GUARDIAN_REGISTRY>

# 5. Governance provisions the baseline and the emergency targets
cast send <BASELINE_FEEDER> \
  "setBaseline(address,address,uint256,uint256,bytes32)" \
  0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4 \
  0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F \
  3 6 \
  0x0000000000000000000000000000000000000000000000000000000000000000

cast send <SAFE_GUARDIAN_REGISTRY> \
  "setTarget(address,bool)" <TARGET> true
```

The baseline can be rotated at any time via `setBaseline` — the trap picks it up on the next `collect()`, no redeploy. `ownersHash` may be left `bytes32(0)` to disable the absolute owners-hash check; relative owners-hash drift is still caught.

## Configuration

`drosera.toml`:

```toml
[traps.bybit_safe_trap_v2]
path = "out/BybitSafeTrapV2.sol/BybitSafeTrapV2.json"
response_contract = "0xYOUR_RESPONDER_V2"        # replace before activation
response_function = "handleIncident(bytes)"
cooldown_period_blocks = 20
min_number_of_operators = 3
max_number_of_operators = 7
block_sample_size = 10
private_trap = true
whitelist = ["0x...", "0x..."]
```

`foundry.toml` requires `via_ir = true` — the 25-field Snapshot exceeds the stack limit without it.

## Assumptions

- The Bybit cold wallet (`0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4`) is a Safe{Wallet} proxy.
- The legitimate Safe singleton is `0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F`.
- Liquid staking tokens (stETH, mETH, cmETH) trade at approximately 1:1 ETH parity for aggregate balance calculations.
- The Drosera operator network achieves 2/3 BLS consensus within the 18-block Bybit response window (~3.6 min at 12 s/block).
- The baseline `(masterCopy, threshold, ownerCount, ownersHash)` is provisioned on-chain via `BaselineFeeder.setBaseline(...)` by a governance multisig + timelock before the trap is activated. `ownersHash` may be left zero to disable the absolute owners-hash check.
- `BaselineFeeder.owner`, `SafeGuardianRegistry.owner`, and the responder's `admin` are deployed behind a real governance multisig + timelock. The contracts are governance-*compatible*; governance-*managed* is a property of operational deployment, not of the source alone.

## Limitations

- **Responder authority is simulated.** The mock target pauses an internal flag. A production deployment needs real `pause()` / approval-revoke / queue-freeze authority granted by the protected protocols.
- **Aggregate balance is approximate.** The trap sums ETH + stETH + mETH + cmETH at face value; a depeg event could cause false positives at boundary thresholds.
- **Single-trigger reporting.** `shouldRespond()` short-circuits. Lower-priority vectors stay silent while a higher-priority one is still firing.
- **Module pagination bound.** The loop caps at 10 pages × 10 modules. Safes with > 100 modules would flag as `MonitoringDegraded` — intentionally, not silently.
- **Root cause is off-chain.** The trap detects the *on-chain consequences* (masterCopy swap, drain, config tamper), not the social-engineering / frontend-injection root cause.

## References

- [CertiK Technical Analysis](https://www.certik.com/blog/bybit-incident-technical-analysis)
- [NCC Group In-Depth Analysis](https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/)
- [CSIS Analysis](https://www.csis.org/analysis/bybit-heist-and-future-us-crypto-regulation)
- [Drosera Developer Docs](https://dev.drosera.io/)
