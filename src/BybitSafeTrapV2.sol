// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "./interfaces/ITrap.sol";

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
 * @notice Production-grade Drosera trap monitoring Safe{Wallet} multisig proxies,
 *         modeled on the Bybit $1.46B hack (2025-02-21) and hardened per
 *         GUIDELINES.md (blockNumber + monitoredTarget in Snapshot, explicit
 *         read-status flags, strict sample ordering, paginated-read completeness,
 *         absolute + relative integrity checks, structured IncidentPayload,
 *         MonitoringDegraded signal).
 *
 *  Emits a structured IncidentPayload consumed by SafeGuardResponderV2.handleIncident(bytes).
 */
contract BybitSafeTrapV2 is ITrap {
    // ======================== Thresholds ========================

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

    // ======================== Baseline constants (Ethereum mainnet) ========================
    //
    // These are the known-good values used for absolute integrity checks in
    // shouldRespond(). Constants (not immutables) because shouldRespond() must
    // be `pure` per ITrap — and `pure` cannot read immutable state.
    //
    // In production, EXPECTED_OWNERS_HASH should be set via an offline,
    // governance-controlled config step before deployment. Left bytes32(0)
    // here disables the absolute owners-hash check; the relative owners-hash
    // check (snapshot-to-snapshot) still catches block-over-block drift.

    address public constant SAFE_PROXY = 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4;
    address public constant EXPECTED_MASTER_COPY = 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;
    uint256 public constant EXPECTED_THRESHOLD = 3;
    uint256 public constant EXPECTED_OWNER_COUNT = 6;
    bytes32 public constant EXPECTED_OWNERS_HASH = bytes32(0);

    address public constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    address public constant METH  = 0xd5F7838F5C461fefF7FE49ea5ebaF7728bB0ADfa;
    address public constant CMETH = 0xe3C063B1BEe9de02eb28352b55D49D85514C67FF;

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

    struct Snapshot {
        // Binding + ordering (required by GUIDELINES §3.2)
        address safeProxy;
        uint256 blockNumber;

        // Explicit read-status flags (GUIDELINES §4)
        bool implementationValid;
        bool masterCopyReadOk;
        bool guardReadOk;
        bool modulesReadComplete;

        // Safe core integrity
        address masterCopy;
        uint256 threshold;
        uint256 ownerCount;
        bytes32 ownersHash;
        uint256 nonce;

        // Modules & guard
        uint256 moduleCount;
        bytes32 modulesHash;
        address guard;

        // Balances
        uint256 ethBalance;
        uint256 stethBalance;
        uint256 methBalance;
        uint256 cmethBalance;
        uint256 aggregateBalance;
    }

    struct IncidentPayload {
        ThreatType threatType;
        address safeProxy;
        uint256 currentBlockNumber;
        uint256 previousBlockNumber;
        bytes details;
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
        uint256 stethBal = _safeBalanceOf(STETH, SAFE_PROXY);
        uint256 methBal = _safeBalanceOf(METH, SAFE_PROXY);
        uint256 cmethBal = _safeBalanceOf(CMETH, SAFE_PROXY);

        uint256 aggregate = ethBal + stethBal + methBal + cmethBal;

        return abi.encode(
            Snapshot({
                safeProxy: SAFE_PROXY,
                blockNumber: block.number,
                implementationValid: implementationValid,
                masterCopyReadOk: masterCopyReadOk,
                guardReadOk: guardReadOk,
                modulesReadComplete: modulesReadComplete,
                masterCopy: masterCopy,
                threshold: threshold,
                ownerCount: ownerCount,
                ownersHash: ownersHash,
                nonce: safeNonce,
                moduleCount: moduleCount,
                modulesHash: modulesHash,
                guard: guard,
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

        // Bind incidents to a specific Safe (GUIDELINES §5 "Strict Sample Ordering").
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

        // 1. MonitoringDegraded — loss of visibility is itself actionable.
        if (!current.masterCopyReadOk || !current.guardReadOk || !current.modulesReadComplete) {
            return _incident(
                ThreatType.MonitoringDegraded,
                current,
                previous,
                abi.encode(
                    current.masterCopyReadOk,
                    current.guardReadOk,
                    current.modulesReadComplete
                )
            );
        }

        // 2. ImplementationCompromised — Bybit primary signal.
        if (!current.implementationValid) {
            return _incident(
                ThreatType.ImplementationCompromised,
                current,
                previous,
                abi.encode(current.threshold, current.ownerCount, current.ownersHash, current.nonce)
            );
        }

        // 3. MasterCopyChanged — absolute baseline integrity check.
        if (current.masterCopy != EXPECTED_MASTER_COPY) {
            return _incident(
                ThreatType.MasterCopyChanged,
                current,
                previous,
                abi.encode(EXPECTED_MASTER_COPY, current.masterCopy)
            );
        }

        // 4. ConfigChanged (absolute) — threshold / owners vs known-good baseline.
        if (
            current.threshold != EXPECTED_THRESHOLD ||
            current.ownerCount != EXPECTED_OWNER_COUNT ||
            (
                EXPECTED_OWNERS_HASH != bytes32(0) &&
                current.ownersHash != EXPECTED_OWNERS_HASH
            )
        ) {
            return _incident(
                ThreatType.ConfigChanged,
                current,
                previous,
                abi.encode(
                    EXPECTED_THRESHOLD,
                    current.threshold,
                    EXPECTED_OWNER_COUNT,
                    current.ownerCount,
                    EXPECTED_OWNERS_HASH,
                    current.ownersHash
                )
            );
        }

        // 5. GuardChanged (relative).
        if (current.guard != previous.guard) {
            return _incident(
                ThreatType.GuardChanged,
                current,
                previous,
                abi.encode(previous.guard, current.guard)
            );
        }

        // 6. ModulesChanged (relative) — only fires when both snapshots had complete reads.
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

        // 7. ConfigChanged (relative) — catches signer drift even with no absolute baseline.
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

        // 8. BalanceDrain — single-block >= 5% drop.
        if (previous.aggregateBalance > 0 && current.aggregateBalance < previous.aggregateBalance) {
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

        // 9. GradualDrain — cumulative >= 15% across the full sample window.
        Snapshot memory oldest = _decodeSnapshot(data[data.length - 1]);
        if (oldest.aggregateBalance > 0 && current.aggregateBalance < oldest.aggregateBalance) {
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

        // 10. NonceJump — abnormal tx velocity.
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

    function _decodeSnapshot(bytes calldata raw) internal pure returns (Snapshot memory s) {
        if (raw.length == 0) {
            return s;
        }
        s = abi.decode(raw, (Snapshot));
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

    function _safeBalanceOf(address token, address account) internal view returns (uint256) {
        uint256 size;
        assembly {
            size := extcodesize(token)
        }
        if (size == 0) return 0;

        try IERC20Like(token).balanceOf(account) returns (uint256 bal) {
            return bal;
        } catch {
            return 0;
        }
    }
}
