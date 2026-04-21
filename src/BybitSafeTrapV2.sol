// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "./interfaces/ITrap.sol";
import {BaselineFeeder} from "./BaselineFeeder.sol";

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
}

interface ISafeLike {
    function getThreshold() external view returns (uint256);
    function nonce() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
    function getStorageAt(uint256 offset, uint256 length)
        external
        view
        returns (bytes memory);
}

/**
 * @title BybitSafeTrapV2
 * @notice Drosera trap monitoring a Safe{Wallet} multisig proxy, modeled on the
 *         Bybit $1.46B hack (2025-02-21). Detects eight distinct threat
 *         classes: implementation compromise, masterCopy swap, guard change,
 *         module change, owner/threshold drift, balance drain (single-block),
 *         gradual drain (window), and nonce velocity.
 *
 *         Operational model:
 *         - The monitored Safe, the BaselineFeeder, and the LST token addresses
 *           are provided via constructor (all immutable) so the same bytecode
 *           deploys against any Safe without source edits.
 *         - Expected/baseline values (masterCopy, threshold, owner count,
 *           ownersHash) live in a BaselineFeeder governed by a multisig; the
 *           trap reads them at `collect()` and embeds them in every snapshot,
 *           so `shouldRespond()` (pure) can compare without state access.
 *         - Every fallible read has an explicit `xxxReadOk` flag. Loss of
 *           visibility (Safe probe, masterCopy read, guard read, module read,
 *           token balance read) short-circuits to MonitoringDegraded instead
 *           of being silently conflated with a "clean" zero.
 *         - `shouldRespond()` is wrapped in length-checked manual calldata
 *           parsing so malformed samples fail closed to `(false, "")` rather
 *           than reverting the operator's call.
 */
contract BybitSafeTrapV2 is ITrap {
    // ======================== Tunables ========================

    uint256 internal constant BPS = 10_000;
    uint256 internal constant SAMPLE_SIZE = 10;

    uint256 internal constant SINGLE_BLOCK_DRAIN_BPS = 500;     // 5%
    uint256 internal constant GRADUAL_DRAIN_BPS = 1500;         // 15%
    uint256 internal constant MAX_NONCE_JUMP = 5;

    uint256 internal constant MAX_MODULE_PAGES = 10;
    uint256 internal constant MODULES_PER_PAGE = 10;

    /// @notice keccak256("guard_manager.guard.address")
    uint256 internal constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    address internal constant SAFE_SENTINEL = address(0x1);

    // ======================== Types ========================

    enum ThreatType {
        None,
        MonitoringDegraded,
        ImplementationCompromised,
        MasterCopyChanged,
        ModulesChanged,
        GuardChanged,
        ConfigChanged,
        BalanceDrain,
        GradualDrain,
        NonceJump
    }

    /// @dev 25 value-typed fields, each encoding to a single 32-byte slot.
    ///      Total abi.encode length = ENCODED_SNAPSHOT_LEN.
    struct Snapshot {
        // Binding + ordering
        address safeProxy;              //  0
        uint256 blockNumber;            //  1

        // Read-status flags (explicit, no address(0)-as-sentinel ambiguity)
        bool implementationValid;       //  2
        bool masterCopyReadOk;          //  3
        bool guardReadOk;               //  4
        bool modulesReadComplete;       //  5
        bool balancesReadOk;            //  6  (aggregate of LST balanceOf reads)
        bool baselineConfigured;        //  7  (true if feeder has a baseline for this Safe)

        // Safe core integrity
        address masterCopy;             //  8
        uint256 threshold;              //  9
        uint256 ownerCount;             // 10
        bytes32 ownersHash;             // 11
        uint256 nonce;                  // 12

        // Modules & guard
        uint256 moduleCount;            // 13
        bytes32 modulesHash;            // 14
        address guard;                  // 15

        // Expected/baseline values (read from feeder at collect-time)
        address expectedMasterCopy;     // 16
        uint256 expectedThreshold;      // 17
        uint256 expectedOwnerCount;     // 18
        bytes32 expectedOwnersHash;     // 19

        // Balances
        uint256 ethBalance;             // 20
        uint256 stethBalance;           // 21
        uint256 methBalance;            // 22
        uint256 cmethBalance;           // 23
        uint256 aggregateBalance;       // 24
    }

    uint256 internal constant SNAPSHOT_FIELDS = 25;
    uint256 internal constant ENCODED_SNAPSHOT_LEN = SNAPSHOT_FIELDS * 32;

    struct IncidentPayload {
        ThreatType threatType;
        address safeProxy;
        uint256 currentBlockNumber;
        uint256 previousBlockNumber;
        bytes details;
    }

    // ======================== Immutables (deploy-time config) ========================

    address public immutable SAFE_PROXY;
    address public immutable BASELINE_FEEDER;

    address public immutable STETH;
    address public immutable METH;
    address public immutable CMETH;

    /// @param safeProxy_       The Safe{Wallet} multisig proxy being monitored.
    /// @param baselineFeeder_  BaselineFeeder contract carrying governance-approved expected values.
    /// @param steth_           stETH token address, or address(0) to disable that read.
    /// @param meth_            mETH token address, or address(0) to disable that read.
    /// @param cmeth_           cmETH token address, or address(0) to disable that read.
    constructor(
        address safeProxy_,
        address baselineFeeder_,
        address steth_,
        address meth_,
        address cmeth_
    ) {
        require(safeProxy_ != address(0), "zero safe");
        require(baselineFeeder_ != address(0), "zero feeder");
        SAFE_PROXY = safeProxy_;
        BASELINE_FEEDER = baselineFeeder_;
        STETH = steth_;
        METH = meth_;
        CMETH = cmeth_;
    }

    // ======================== collect() ========================

    function collect() external view returns (bytes memory) {
        (
            bool implementationValid,
            uint256 threshold,
            uint256 ownerCount,
            bytes32 ownersHash,
            uint256 safeNonce
        ) = _probeSafeImplementation(SAFE_PROXY);

        (bool masterCopyReadOk, address masterCopy) = _readMasterCopy(SAFE_PROXY);
        (bool modulesReadComplete, uint256 moduleCount, bytes32 modulesHash) = _readModules(SAFE_PROXY);
        (bool guardReadOk, address guard) = _readGuard(SAFE_PROXY);

        uint256 ethBal = SAFE_PROXY.balance;
        (bool stethOk, uint256 stethBal) = _safeBalanceOf(STETH, SAFE_PROXY);
        (bool methOk, uint256 methBal) = _safeBalanceOf(METH, SAFE_PROXY);
        (bool cmethOk, uint256 cmethBal) = _safeBalanceOf(CMETH, SAFE_PROXY);
        bool balancesReadOk = stethOk && methOk && cmethOk;

        // Only sum balances we actually read successfully — otherwise a failed
        // read could masquerade as a drain.
        uint256 aggregate = ethBal;
        if (stethOk) aggregate += stethBal;
        if (methOk) aggregate += methBal;
        if (cmethOk) aggregate += cmethBal;

        BaselineFeeder.Baseline memory baseline = _readBaseline(SAFE_PROXY);

        return abi.encode(
            Snapshot({
                safeProxy: SAFE_PROXY,
                blockNumber: block.number,
                implementationValid: implementationValid,
                masterCopyReadOk: masterCopyReadOk,
                guardReadOk: guardReadOk,
                modulesReadComplete: modulesReadComplete,
                balancesReadOk: balancesReadOk,
                baselineConfigured: baseline.configured,
                masterCopy: masterCopy,
                threshold: threshold,
                ownerCount: ownerCount,
                ownersHash: ownersHash,
                nonce: safeNonce,
                moduleCount: moduleCount,
                modulesHash: modulesHash,
                guard: guard,
                expectedMasterCopy: baseline.masterCopy,
                expectedThreshold: baseline.threshold,
                expectedOwnerCount: baseline.ownerCount,
                expectedOwnersHash: baseline.ownersHash,
                ethBalance: ethBal,
                stethBalance: stethBal,
                methBalance: methBal,
                cmethBalance: cmethBal,
                aggregateBalance: aggregate
            })
        );
    }

    // ======================== shouldRespond() ========================

    function shouldRespond(bytes[] calldata data) external pure returns (bool, bytes memory) {
        if (data.length < 2 || data.length > SAMPLE_SIZE) {
            return (false, bytes(""));
        }

        Snapshot memory current = _decodeSnapshot(data[0]);
        Snapshot memory previous = _decodeSnapshot(data[1]);

        // Bind incidents to a specific Safe. Zero safeProxy signals a decode
        // failure (the decoder returns an all-zero snapshot on any length
        // mismatch) — treat it like malformed input and fail closed.
        if (current.safeProxy == address(0) || previous.safeProxy != current.safeProxy) {
            return (false, bytes(""));
        }

        // Strict newest -> oldest contiguous sample ordering across the full window.
        for (uint256 i = 1; i < data.length; i++) {
            Snapshot memory newer = _decodeSnapshot(data[i - 1]);
            Snapshot memory older = _decodeSnapshot(data[i]);
            if (
                newer.blockNumber == 0 ||
                older.blockNumber == 0 ||
                newer.blockNumber != older.blockNumber + 1 ||
                older.safeProxy != current.safeProxy
            ) {
                return (false, bytes(""));
            }
        }

        // EXPLOIT:   Attacker may disable or obscure Safe introspection (e.g. swap
        //            masterCopy to a contract whose getStorageAt/getModulesPaginated
        //            revert, or poison an LST read) to blind defenders before the
        //            drain tx.
        // DETECTION: Any fallible read sets its xxxReadOk flag to false, including
        //            aggregate balancesReadOk across stETH/mETH/cmETH. Loss of
        //            visibility is itself actionable — pause before damage.
        if (
            !current.masterCopyReadOk ||
            !current.guardReadOk ||
            !current.modulesReadComplete ||
            !current.balancesReadOk
        ) {
            return _incident(
                ThreatType.MonitoringDegraded,
                current,
                previous,
                abi.encode(
                    current.masterCopyReadOk,
                    current.guardReadOk,
                    current.modulesReadComplete,
                    current.balancesReadOk
                )
            );
        }

        // EXPLOIT:   Bybit (2025-02-21, block 21,895,238) — delegatecall swapped
        //            the Safe{Wallet} masterCopy to a malicious implementation;
        //            afterwards getThreshold()/getOwners()/nonce() reverted or
        //            returned garbage, immediately preceding the $1.46B drain.
        // DETECTION: _probeSafeImplementation() sets implementationValid=false
        //            when any of those three reads revert or when threshold is
        //            inconsistent with ownerCount. Primary Bybit signal.
        if (!current.implementationValid) {
            return _incident(
                ThreatType.ImplementationCompromised,
                current,
                previous,
                abi.encode(current.threshold, current.ownerCount, current.ownersHash, current.nonce)
            );
        }

        // EXPLOIT:   Bybit attack wrote a new masterCopy address into Safe
        //            storage slot 0 via a crafted delegatecall.
        // DETECTION: _readMasterCopy reads slot 0 via getStorageAt(0,1); any
        //            deviation from the feeder-supplied baseline triggers even
        //            if the malicious impl keeps the view ABI working.
        //            Gated on baselineConfigured so an unconfigured feeder
        //            entry cannot produce a false positive against address(0).
        if (current.baselineConfigured && current.masterCopy != current.expectedMasterCopy) {
            return _incident(
                ThreatType.MasterCopyChanged,
                current,
                previous,
                abi.encode(current.expectedMasterCopy, current.masterCopy)
            );
        }

        // EXPLOIT:   Alternative vector — attacker reduces threshold, removes
        //            owners, or swaps the owner set to keys they control,
        //            allowing unilateral treasury moves.
        // DETECTION: Absolute comparison against the feeder baseline. ownersHash
        //            check is skipped when baseline.ownersHash == bytes32(0) so
        //            deployments that haven't captured a full owners snapshot
        //            still benefit from threshold/count enforcement.
        if (
            current.baselineConfigured && (
                current.threshold != current.expectedThreshold ||
                current.ownerCount != current.expectedOwnerCount ||
                (
                    current.expectedOwnersHash != bytes32(0) &&
                    current.ownersHash != current.expectedOwnersHash
                )
            )
        ) {
            return _incident(
                ThreatType.ConfigChanged,
                current,
                previous,
                abi.encode(
                    current.expectedThreshold,
                    current.threshold,
                    current.expectedOwnerCount,
                    current.ownerCount,
                    current.expectedOwnersHash,
                    current.ownersHash
                )
            );
        }

        // EXPLOIT:   Attacker clears or replaces the Safe transaction guard
        //            (setGuard()) to silence the defensive pre-exec hook before
        //            draining.
        // DETECTION: Relative check — current.guard != previous.guard flags any
        //            block-over-block change.
        if (current.guard != previous.guard) {
            return _incident(
                ThreatType.GuardChanged,
                current,
                previous,
                abi.encode(previous.guard, current.guard)
            );
        }

        // EXPLOIT:   enableModule() installs a module that can execTransactionFromModule
        //            with no owner signatures — a classic multisig backdoor.
        // DETECTION: Relative diff of moduleCount / modulesHash across the paginated
        //            read. Gated on previous.modulesReadComplete so a one-block
        //            paging failure does not produce a false positive.
        if (
            previous.modulesReadComplete && (
                current.moduleCount != previous.moduleCount ||
                current.modulesHash != previous.modulesHash
            )
        ) {
            return _incident(
                ThreatType.ModulesChanged,
                current,
                previous,
                abi.encode(previous.moduleCount, current.moduleCount, previous.modulesHash, current.modulesHash)
            );
        }

        // EXPLOIT:   Signer-set drift (addOwnerWithThreshold / swapOwner / etc.)
        //            short of tripping the absolute baseline — e.g. deployments
        //            where the feeder's ownersHash is left bytes32(0).
        // DETECTION: Block-over-block diff of threshold / ownerCount / ownersHash
        //            catches drift even without a governance-supplied baseline.
        if (
            current.threshold != previous.threshold ||
            current.ownerCount != previous.ownerCount ||
            current.ownersHash != previous.ownersHash
        ) {
            return _incident(
                ThreatType.ConfigChanged,
                current,
                previous,
                abi.encode(
                    previous.threshold,
                    current.threshold,
                    previous.ownerCount,
                    current.ownerCount,
                    previous.ownersHash,
                    current.ownersHash
                )
            );
        }

        // EXPLOIT:   Primary Bybit damage — ~400k ETH / stETH / mETH / cmETH
        //            swept out of the cold wallet in a single block after the
        //            masterCopy swap.
        // DETECTION: Aggregate ETH + LST balance drop of >= 5% in one block.
        //            Gated on previous.balancesReadOk so a degraded prior read
        //            cannot masquerade as a drain.
        if (
            previous.balancesReadOk &&
            previous.aggregateBalance > 0 &&
            current.aggregateBalance < previous.aggregateBalance
        ) {
            uint256 drop = previous.aggregateBalance - current.aggregateBalance;
            uint256 dropBps = (drop * BPS) / previous.aggregateBalance;

            if (dropBps >= SINGLE_BLOCK_DRAIN_BPS) {
                return _incident(
                    ThreatType.BalanceDrain,
                    current,
                    previous,
                    abi.encode(previous.aggregateBalance, current.aggregateBalance, dropBps)
                );
            }
        }

        // EXPLOIT:   Stealth variant — attacker paces withdrawals across multiple
        //            blocks to stay under the single-block 5% threshold.
        // DETECTION: Cumulative >= 15% drop between oldest and newest snapshot in
        //            the configured window (block_sample_size). Gated on
        //            oldest.balancesReadOk for the same reason as above.
        Snapshot memory oldest = _decodeSnapshot(data[data.length - 1]);
        if (
            oldest.balancesReadOk &&
            oldest.aggregateBalance > 0 &&
            current.aggregateBalance < oldest.aggregateBalance
        ) {
            uint256 cumulativeDrop = oldest.aggregateBalance - current.aggregateBalance;
            uint256 cumulativeDropBps = (cumulativeDrop * BPS) / oldest.aggregateBalance;

            if (cumulativeDropBps >= GRADUAL_DRAIN_BPS) {
                return _incident(
                    ThreatType.GradualDrain,
                    current,
                    oldest,
                    abi.encode(oldest.aggregateBalance, current.aggregateBalance, cumulativeDropBps)
                );
            }
        }

        // EXPLOIT:   Post-compromise the attacker may batch multiple Safe
        //            execTransaction calls back-to-back, advancing the nonce
        //            faster than any legitimate operational cadence.
        // DETECTION: nonce delta vs previous snapshot greater than MAX_NONCE_JUMP.
        if (current.nonce > previous.nonce && (current.nonce - previous.nonce) > MAX_NONCE_JUMP) {
            return _incident(
                ThreatType.NonceJump,
                current,
                previous,
                abi.encode(previous.nonce, current.nonce)
            );
        }

        return (false, bytes(""));
    }

    // ======================== Internal ========================

    function _incident(
        ThreatType threatType,
        Snapshot memory current,
        Snapshot memory previous,
        bytes memory details
    ) internal pure returns (bool, bytes memory) {
        IncidentPayload memory payload = IncidentPayload({
            threatType: threatType,
            safeProxy: current.safeProxy,
            currentBlockNumber: current.blockNumber,
            previousBlockNumber: previous.blockNumber,
            details: details
        });
        return (true, abi.encode(payload));
    }

    /// @dev Robust snapshot decoder. Returns an all-zero Snapshot on any length
    ///      mismatch, and manually parses each 32-byte slot so malformed bool
    ///      patterns (which would revert abi.decode) fail closed instead.
    ///
    ///      Snapshot has no dynamic-type fields, so abi.encode produces exactly
    ///      ENCODED_SNAPSHOT_LEN bytes. Any other length is malformed.
    function _decodeSnapshot(bytes calldata raw) internal pure returns (Snapshot memory s) {
        if (raw.length != ENCODED_SNAPSHOT_LEN) {
            return s;
        }

        s.safeProxy              = _addrAt(raw,  0);
        s.blockNumber            = _uintAt(raw,  1);
        s.implementationValid    = _boolAt(raw,  2);
        s.masterCopyReadOk       = _boolAt(raw,  3);
        s.guardReadOk            = _boolAt(raw,  4);
        s.modulesReadComplete    = _boolAt(raw,  5);
        s.balancesReadOk         = _boolAt(raw,  6);
        s.baselineConfigured     = _boolAt(raw,  7);
        s.masterCopy             = _addrAt(raw,  8);
        s.threshold              = _uintAt(raw,  9);
        s.ownerCount             = _uintAt(raw, 10);
        s.ownersHash             = _bytes32At(raw, 11);
        s.nonce                  = _uintAt(raw, 12);
        s.moduleCount            = _uintAt(raw, 13);
        s.modulesHash            = _bytes32At(raw, 14);
        s.guard                  = _addrAt(raw, 15);
        s.expectedMasterCopy     = _addrAt(raw, 16);
        s.expectedThreshold      = _uintAt(raw, 17);
        s.expectedOwnerCount     = _uintAt(raw, 18);
        s.expectedOwnersHash     = _bytes32At(raw, 19);
        s.ethBalance             = _uintAt(raw, 20);
        s.stethBalance           = _uintAt(raw, 21);
        s.methBalance            = _uintAt(raw, 22);
        s.cmethBalance           = _uintAt(raw, 23);
        s.aggregateBalance       = _uintAt(raw, 24);
    }

    function _wordAt(bytes calldata raw, uint256 i) private pure returns (bytes32 w) {
        assembly {
            w := calldataload(add(raw.offset, mul(i, 32)))
        }
    }

    function _uintAt(bytes calldata raw, uint256 i) private pure returns (uint256) {
        return uint256(_wordAt(raw, i));
    }

    function _addrAt(bytes calldata raw, uint256 i) private pure returns (address) {
        return address(uint160(uint256(_wordAt(raw, i))));
    }

    function _bytes32At(bytes calldata raw, uint256 i) private pure returns (bytes32) {
        return _wordAt(raw, i);
    }

    /// @dev Parses the last byte of the slot as the bool value. Permissive by
    ///      design: abi.encode(true) produces 0x...01, and any nonzero last
    ///      byte is treated as true. Never reverts on malformed input.
    function _boolAt(bytes calldata raw, uint256 i) private pure returns (bool) {
        return uint256(_wordAt(raw, i)) != 0;
    }

    function _probeSafeImplementation(address safe)
        internal
        view
        returns (bool, uint256, uint256, bytes32, uint256)
    {
        uint256 size;
        assembly {
            size := extcodesize(safe)
        }
        if (size == 0) return (false, 0, 0, bytes32(0), 0);

        uint256 threshold;
        try ISafeLike(safe).getThreshold() returns (uint256 t) {
            threshold = t;
        } catch {
            return (false, 0, 0, bytes32(0), 0);
        }

        uint256 ownerCount;
        bytes32 ownersHash;
        try ISafeLike(safe).getOwners() returns (address[] memory owners) {
            ownerCount = owners.length;
            ownersHash = keccak256(abi.encode(owners));
        } catch {
            return (false, 0, 0, bytes32(0), 0);
        }

        uint256 safeNonce;
        try ISafeLike(safe).nonce() returns (uint256 n) {
            safeNonce = n;
        } catch {
            return (false, 0, 0, bytes32(0), 0);
        }

        if (threshold == 0 || threshold > ownerCount) {
            return (false, threshold, ownerCount, ownersHash, safeNonce);
        }

        return (true, threshold, ownerCount, ownersHash, safeNonce);
    }

    function _readMasterCopy(address safe) internal view returns (bool, address) {
        try ISafeLike(safe).getStorageAt(0, 1) returns (bytes memory result) {
            if (result.length >= 32) {
                return (true, address(uint160(uint256(bytes32(result)))));
            }
            return (false, address(0));
        } catch {
            return (false, address(0));
        }
    }

    function _readGuard(address safe) internal view returns (bool, address) {
        try ISafeLike(safe).getStorageAt(GUARD_STORAGE_SLOT, 1) returns (bytes memory result) {
            if (result.length >= 32) {
                return (true, address(uint160(uint256(bytes32(result)))));
            }
            return (false, address(0));
        } catch {
            return (false, address(0));
        }
    }

    function _readModules(address safe) internal view returns (bool, uint256, bytes32) {
        address start = SAFE_SENTINEL;
        uint256 totalCount = 0;
        bytes32 runningHash = bytes32(0);

        for (uint256 page = 0; page < MAX_MODULE_PAGES; page++) {
            try ISafeLike(safe).getModulesPaginated(start, MODULES_PER_PAGE)
                returns (address[] memory modules, address next)
            {
                totalCount += modules.length;
                runningHash = keccak256(abi.encode(runningHash, modules));

                if (next == SAFE_SENTINEL || next == address(0) || modules.length == 0) {
                    return (true, totalCount, runningHash);
                }

                start = next;
            } catch {
                return (false, totalCount, runningHash);
            }
        }

        // Hit page cap without reaching sentinel — treat as incomplete.
        return (false, totalCount, runningHash);
    }

    /// @dev Returns (ok, balance). `ok` distinguishes:
    ///      - token is address(0)            -> (true, 0)   [not configured for this Safe]
    ///      - token has no code              -> (false, 0)  [misconfig or environmental]
    ///      - balanceOf reverted             -> (false, 0)  [compromised or DoS'd token]
    ///      - call succeeded                 -> (true, bal)
    function _safeBalanceOf(address token, address account) internal view returns (bool, uint256) {
        if (token == address(0)) return (true, 0);

        uint256 size;
        assembly {
            size := extcodesize(token)
        }
        if (size == 0) return (false, 0);

        try IERC20Like(token).balanceOf(account) returns (uint256 bal) {
            return (true, bal);
        } catch {
            return (false, 0);
        }
    }

    function _readBaseline(address safe) internal view returns (BaselineFeeder.Baseline memory b) {
        try BaselineFeeder(BASELINE_FEEDER).getBaseline(safe) returns (BaselineFeeder.Baseline memory out) {
            return out;
        } catch {
            return b;
        }
    }
}
