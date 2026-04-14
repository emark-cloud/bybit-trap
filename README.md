# Bybit Safe{Wallet} Exploit Trap

**Drosera Monitoring Tech Demo — Bybit $1.46B Hack (February 21, 2025)**

A working monitoring-and-alert trap that demonstrates how Drosera could have detected the Bybit Safe{Wallet} compromise across 8 independent detection vectors, paired with a mock emergency responder.

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

## How Drosera Would Have Detected It

This trap monitors Safe{Wallet} multisigs across **8 detection vectors**, covering the Bybit-specific attack and generalized multisig compromise patterns.

### The 18-Block Window

The masterCopy swap and the fund drain happened in **separate blocks**. Drosera operators monitoring every block would have detected the implementation swap at block 21,895,238 — **18 blocks before** the $1.46B drain at block 21,895,256. This is sufficient time for a Drosera consensus (2/3 operator agreement via BLS signatures) to form and submit a response transaction.

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

### Test Results (13/13 passing)

| Test | What it verifies |
|------|-----------------|
| `test_PreExploitState` | Pre-exploit state is normal — implementation valid, balances intact, correct masterCopy |
| `test_PostSwapState` | Post-swap state — Safe functions revert, implementation flagged invalid |
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
| `test_ResponderIntegration` | End-to-end: responder receives incident, pauses, rejects unauthorized callers, admin unpauses |

Tests fork Ethereum mainnet at the actual exploit blocks (21,895,237 — 21,895,256) and verify detection against real on-chain state.

## Project Structure

```
src/
  BybitSafeTrap.sol       # The Drosera trap contract (8 detection vectors)
  SafeGuardResponder.sol  # Mock emergency responder with allowlist auth
test/
  BybitSafeTrap.t.sol     # Foundry tests against real exploit blocks (13 tests)
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

## Limitations

This is a **monitoring-and-alert tech demo**, not a fully wired prevention system. For a complete prevention layer, you would additionally need:

- **Real on-chain authority**: The mock responder pauses a flag but has no actual control over the Safe wallet or dependent protocols. A production responder would need to call `pause()` on downstream contracts, revoke approvals via a guardian, or freeze timelock queues.
- **Correct executor wiring**: The allowlist must be populated with the actual addresses that submit response transactions in your Drosera deployment.
- **Aggregate balance is approximate**: `aggregateBalance` sums ETH + stETH + mETH + cmETH at face value, assuming ~1:1 ETH parity. This is not a true market valuation — depegs or rebasing could cause false positives or missed triggers.
- **Single-trigger reporting**: `shouldRespond()` short-circuits on the first detected anomaly. If multiple vectors fire simultaneously, only the highest-priority one is reported. A bitmask approach would improve incident richness.
- **Implementation validity noise**: If Safe function calls revert for reasons unrelated to compromise (e.g., RPC issues, unusual proxy configurations), the trap will fire. Cross-confirmation with the masterCopy slot check would reduce false positives.
- **Module pagination bounds**: Module enumeration iterates up to 100 modules (10 pages x 10 per page). Safes with more than 100 modules (extremely unlikely) would have partial coverage.

## References

- [CertiK Technical Analysis](https://www.certik.com/blog/bybit-incident-technical-analysis)
- [NCC Group In-Depth Analysis](https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/)
- [CSIS Analysis](https://www.csis.org/analysis/bybit-heist-and-future-us-crypto-regulation)
- [Drosera Developer Docs](https://dev.drosera.io/)
