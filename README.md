# Bybit Safe{Wallet} Exploit Trap

**Operation Flytrap PoC -- Bybit $1.46B Hack (February 21, 2025)**

A production-grade Drosera trap demonstrating how the protocol would have detected and contained the largest cryptocurrency theft in history. Includes a complete exploit reproduction (Part 1), 8-vector detection trap with response path (Part 2), and 30 passing Foundry tests covering trigger behavior, edge cases, boundary thresholds, sample ordering, and end-to-end response flow.

## The Attack

On February 21, 2025, the Bybit exchange suffered the largest cryptocurrency theft in history. The Lazarus Group (North Korea) stole **$1.46 billion** in ETH and liquid staking tokens from Bybit's cold wallet — a Safe{Wallet} multisig.

### How It Happened

1. **Feb 4**: Attacker compromised a Safe{Wallet} developer's macOS machine via social engineering
2. **Feb 18**: Attacker deployed two malicious contracts on Ethereum
3. **Feb 21, Block 21,895,238**: Exploit executed
   - Malicious JS injected into Safe's frontend showed Bybit signers a legitimate-looking transfer
   - The actual payload was a `delegatecall` (operation=1) to the attacker's contract
   - The attacker's contract had a `transfer(address,uint256)` function that wrote its first argument into **storage slot 0**, overwriting the Safe proxy's `masterCopy` (implementation address)
   - With `masterCopy` pointing to a malicious implementation, the attacker called backdoor functions to drain all funds
4. **Block 21,895,256**: All ETH drained (18 blocks after the masterCopy swap)

### Stolen Assets
- 401,346 ETH
- 90,375 stETH
- 8,000 mETH
- 15,000 cmETH

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
| **Scope** | Implementation compromise, configuration tampering, balance anomalies across 8 vectors |
| **What it does NOT protect against** | Social engineering of signers, frontend supply-chain attacks (the root cause of Bybit), off-chain key compromise without on-chain state changes |

## How Drosera Would Have Detected It

This trap monitors Safe{Wallet} multisigs across **8 detection vectors**, covering the Bybit-specific attack and generalized multisig compromise patterns.

### The 18-Block Window

The masterCopy swap and the fund drain happened in **separate blocks**. Drosera operators monitoring every block would have detected the implementation swap at block 21,895,238 -- **18 blocks before** the $1.46B drain at block 21,895,256. This is sufficient time for a Drosera consensus (2/3 operator agreement via BLS signatures) to form and submit a response transaction.

### Detection Vectors

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | Implementation compromise | CRITICAL | Calls Safe-specific functions (`getThreshold()`, `getOwners()`, `nonce()`). If the masterCopy was swapped to a contract that doesn't implement them, all calls revert — a definitive compromise signal. This is exactly what happened in the Bybit hack. |
| 2 | Subtle masterCopy swap | CRITICAL | Reads storage slot 0 directly via `getStorageAt()` and compares against the known-good singleton address. Catches sophisticated attacks where the new implementation still implements Safe functions but contains backdoor logic. |
| 3 | Module additions | CRITICAL | Monitors `getModulesPaginated()` (all pages) for unauthorized module installations. A malicious module can bypass multisig requirements entirely, executing transactions without owner signatures. |
| 4 | Guard removal/change | CRITICAL | Reads the guard manager storage slot (`keccak256("guard_manager.guard.address")`). Transaction guards enforce invariants on every Safe transaction — removing or replacing one can disable critical safety checks. |
| 5 | Threshold/owner manipulation | CRITICAL | Hashes the full owner array (`keccak256(abi.encode(getOwners()))`) and tracks the signing threshold. Detects any signer set change — additions, removals, or replacements — even when the owner count stays the same. |
| 6 | Catastrophic balance drain | CRITICAL | Fires if the aggregate balance drops by more than **5%** between consecutive blocks. |
| 7 | Gradual drain | WARNING | Compares the newest snapshot against the oldest in the data window. Fires if the cumulative drop exceeds **15%** — catching slow bleeds that stay under the single-block threshold. |
| 8 | Nonce jump | WARNING | Detects a nonce increment greater than **5** between consecutive blocks, indicating rapid batch transaction execution that could signal an automated exploit. |

### Response Payload

All vectors return a standardized payload: `abi.encode(uint8 threatType, bytes details)`, matching the responder's `handleIncident(uint8,bytes)` interface. This ensures the callback path is correctly wired end-to-end.

### What's Collected Each Block

The trap's `collect()` function builds a `Snapshot` struct every block:

```
implementationValid  — do Safe functions respond?
masterCopy           — slot 0 direct read (actual implementation address)
threshold            — signing threshold
ownerCount           — number of owners
ownersHash           — keccak256 of the full owner array
nonce                — Safe transaction nonce
moduleCount          — number of enabled modules (all pages)
modulesHash          — incremental keccak256 across all module pages
guard                — transaction guard address
ethBalance           — ETH held
stethBalance         — stETH held
methBalance          — mETH held
cmethBalance         — cmETH held
aggregateBalance     — raw sum of all balances (~1:1 ETH parity assumption)
```

## Running the Tests

```bash
# Install dependencies
bun install

# Build
forge build

# Run all tests (requires archive node RPC)
forge test --contracts test/BybitSafeTrap.t.sol -vv
```

### Test Results (30/30 passing)

#### Exploit Reproduction (Part 1)
| Test | What it verifies |
|------|-----------------|
| `test_ExploitReproduction_BybitAttack` | Step-by-step replay: pre-exploit state -> masterCopy swap -> fund drain -> Drosera detection. Asserts >400k ETH present pre-exploit, slot 0 overwritten, Safe functions revert, >90% funds lost, trap fires at swap block |

#### Core Detection (Part 2)
| Test | What it verifies |
|------|-----------------|
| `test_PreExploitState` | Pre-exploit state is normal -- implementation valid, balances intact, correct masterCopy |
| `test_PostSwapState` | Post-swap state -- Safe functions revert, implementation flagged invalid |
| `test_DetectsImplementationSwap` | `shouldRespond()` fires with threat type 1 on implementation swap |
| `test_DetectsBalanceDrain` | Balance drain detected as secondary signal (threat type 6) |
| `test_NoFalsePositive` | No false positives during normal operation across consecutive blocks |
| `test_FullOperatorFlow` | Full operator simulation with 5 block samples detects the exploit |
| `test_DetectsSubtleMasterCopySwap` | Detects slot 0 change when Safe functions still work (threat type 2) |
| `test_DetectsModuleAddition` | Detects unauthorized module installation (threat type 3) |
| `test_DetectsGuardRemoval` | Detects transaction guard removal (threat type 4) |
| `test_DetectsOwnerSetChange` | Detects signer set change with same owner count (threat type 5) |
| `test_DetectsGradualDrain` | Detects cumulative >15% drain across 10-block window (threat type 7) |
| `test_DetectsNonceJump` | Detects rapid nonce increment >5 between blocks (threat type 8) |

#### Edge Cases
| Test | What it verifies |
|------|-----------------|
| `test_EdgeCase_EmptyDataArray` | Empty data[] returns (false, "") -- no revert |
| `test_EdgeCase_SingleSample` | Single sample (no comparison) returns (false, "") |
| `test_EdgeCase_ZeroLengthCurrentSample` | Zero-length data[0] returns (false, "") |
| `test_EdgeCase_ZeroLengthPreviousSample` | Zero-length data[1] returns (false, "") |
| `test_EdgeCase_MalformedBytes` | Malformed (too-short) bytes return (false, "") -- no revert |
| `test_EdgeCase_BothSamplesEmpty` | Both samples zero-length returns (false, "") |

#### Boundary Thresholds
| Test | What it verifies |
|------|-----------------|
| `test_Boundary_BalanceDrain_BelowThreshold` | 499 bps (4.99%) drop does NOT trigger |
| `test_Boundary_BalanceDrain_AtThreshold` | 500 bps (5.00%) drop DOES trigger |
| `test_Boundary_BalanceDrain_AboveThreshold` | 501 bps (5.01%) drop DOES trigger |
| `test_Boundary_NonceJump_AtLimit` | Nonce jump of 5 does NOT trigger (threshold is >5) |
| `test_Boundary_NonceJump_AboveLimit` | Nonce jump of 6 DOES trigger |
| `test_Boundary_GradualDrain_BelowThreshold` | 1499 bps cumulative drop does NOT trigger |
| `test_Boundary_GradualDrain_AtThreshold` | 1500 bps cumulative drop DOES trigger |

#### Sample Ordering
| Test | What it verifies |
|------|-----------------|
| `test_SampleOrdering_SwappedOrderNoFalsePositive` | Increasing balance (recovery) does NOT trigger drain detection |
| `test_SampleOrdering_IdenticalSnapshots` | Identical consecutive snapshots do NOT trigger |

#### Responder Integration
| Test | What it verifies |
|------|-----------------|
| `test_ResponderIntegration` | Responder receives incident, pauses, rejects unauthorized callers, admin unpauses |
| `test_EndToEnd_DetectRespondContain` | Full cycle: trap detects at real exploit block -> payload passed to responder -> operations pause -> admin resolves. Proves payload alignment end-to-end |

Tests fork Ethereum mainnet at the actual exploit blocks (21,895,237 -- 21,895,256) and verify detection against real on-chain state.

## Project Structure

```
src/
  BybitSafeTrap.sol       # The Drosera trap contract (8 detection vectors, "Show Your Work" comments)
  SafeGuardResponder.sol  # Emergency responder with allowlist auth, pause/unpause, incident logging
test/
  BybitSafeTrap.t.sol     # 30 Foundry tests: exploit reproduction, detection, edge cases, boundaries, e2e
drosera.toml              # Drosera deployment config (block_sample_size = 10)
foundry.toml              # Foundry config with archive RPC
```

## Configuration

The `drosera.toml` configures the trap for deployment:

```toml
[traps.bybit_safe_trap]
path = "out/BybitSafeTrap.sol/BybitSafeTrap.json"
response_contract = "0x..."              # Deployed SafeGuardResponder address
response_function = "handleIncident(uint8,bytes)"
block_sample_size = 10                   # 10-block window for gradual drain detection
cooldown_period_blocks = 20
min_number_of_operators = 1
max_number_of_operators = 5
private_trap = true                      # Bytecode stays off-chain (hidden security intent)
```

The `SafeGuardResponder` uses an allowlist auth model — the admin configures which addresses can call `handleIncident()`. In Drosera, the actual `msg.sender` may be an operator EOA, relayer, or protocol executor.

## Assumptions

- The Bybit cold wallet address (`0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4`) is a Safe{Wallet} proxy
- The legitimate Safe singleton (masterCopy) is `0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F`
- ETH-denominated liquid staking tokens (stETH, mETH, cmETH) trade at approximately 1:1 ETH parity for aggregate balance calculations
- The Drosera operator network achieves consensus within the 18-block response window (~3.6 minutes at 12s/block)
- The response contract has been authorized by downstream protocols to pause their operations

## Limitations

- **Responder authority is simulated**: The `SafeGuardResponder` pauses an internal flag and emits events. A production deployment would need `pause()` calls on downstream contracts, approval revocations, and timelock queue freezes -- requiring actual on-chain authority granted by the protected protocols.
- **Aggregate balance is approximate**: `aggregateBalance` sums ETH + stETH + mETH + cmETH at face value. Depegs or rebasing could cause false positives or missed triggers at boundary thresholds.
- **Single-trigger reporting**: `shouldRespond()` short-circuits on the first detected anomaly. If multiple vectors fire simultaneously, only the highest-priority one is reported.
- **Implementation validity noise**: If Safe function calls revert for reasons unrelated to compromise (e.g., unusual proxy configurations), Vector 1 will fire. Cross-confirmation with Vector 2 (slot 0 check) reduces false positives.
- **Module pagination bounds**: Module enumeration iterates up to 100 modules (10 pages x 10 per page). Safes with more than 100 modules (extremely unlikely) would have partial coverage.
- **Root cause is off-chain**: This trap detects the *on-chain consequences* of the Bybit hack (masterCopy swap, balance drain), not the root cause (compromised developer machine, malicious JS injection). The social engineering attack vector is outside the scope of on-chain monitoring.

## References

- [CertiK Technical Analysis](https://www.certik.com/blog/bybit-incident-technical-analysis)
- [NCC Group In-Depth Analysis](https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/)
- [CSIS Analysis](https://www.csis.org/analysis/bybit-heist-and-future-us-crypto-regulation)
- [Drosera Developer Docs](https://dev.drosera.io/)
