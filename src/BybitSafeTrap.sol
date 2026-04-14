// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrap} from "drosera-contracts/interfaces/ITrap.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Interface for Safe{Wallet} functions used for monitoring.
///         If the proxy's masterCopy is swapped to a malicious contract,
///         Safe-specific calls will revert.
interface ISafe {
    function getThreshold() external view returns (uint256);
    function nonce() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
    function getModulesPaginated(address start, uint256 pageSize)
        external view returns (address[] memory array, address next);
    function getStorageAt(uint256 offset, uint256 length)
        external view returns (bytes memory);
}

/**
 * @title BybitSafeTrap
 * @notice Drosera trap that detects Safe{Wallet} proxy compromise across
 *         multiple attack vectors — modeled on the Bybit $1.46B hack
 *         (February 21, 2025) and generalized for broader multisig protection.
 *
 * @dev Detection vectors:
 *
 *   1. Implementation compromise — Safe-specific functions revert after
 *      masterCopy swap to a contract that doesn't implement them.
 *
 *   2. Subtle masterCopy swap — Reads slot 0 directly via getStorageAt()
 *      to detect swaps where the new implementation still has Safe functions.
 *
 *   3. Module additions — Monitors getModulesPaginated() for unauthorized
 *      module installations that could bypass multisig requirements.
 *
 *   4. Guard removal/change — Reads the guard storage slot to detect
 *      removal or replacement of transaction guards.
 *
 *   5. Threshold/owner manipulation — Hashes the full owner array and
 *      tracks threshold to detect any signer set changes.
 *
 *   6. Catastrophic balance drain (>5%) — Single-block drop threshold.
 *
 *   7. Gradual drain (>15%) — Compares newest vs oldest snapshot across
 *      the full data[] window to catch slow bleeds.
 *
 *   8. Nonce jump — Detects >5 nonce increment between blocks, indicating
 *      rapid transaction execution (potential batch exploit).
 *
 *   Response payload: all vectors return abi.encode(uint8 threatType, bytes details)
 *   matching the responder's handleIncident(uint8,bytes) interface.
 *
 * Fork reference blocks:
 *   - Block 21,895,237 — pre-exploit (balances intact, implementation valid)
 *   - Block 21,895,238 — masterCopy swapped to malicious implementation
 *   - Block 21,895,256 — ETH drained (18-block window for Drosera response)
 *   - Exploit TX: 0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882
 *
 * Key addresses:
 *   - Victim wallet:            0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4
 *   - Attacker EOA:             0x0fa09c3a328792253f8dee7116848723b72a6d2e
 *   - Malicious implementation: 0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516
 *   - Storage manipulator:      0x96221423681A6d52E184D440a8eFCEbB105C7242
 */
contract BybitSafeTrap is ITrap {
    // ======================== Threat Type Constants ========================

    uint8 constant THREAT_IMPLEMENTATION_COMPROMISED = 1;
    uint8 constant THREAT_MASTERCOPY_CHANGED = 2;
    uint8 constant THREAT_MODULES_CHANGED = 3;
    uint8 constant THREAT_GUARD_CHANGED = 4;
    uint8 constant THREAT_CONFIG_CHANGED = 5;
    uint8 constant THREAT_BALANCE_DRAIN = 6;
    uint8 constant THREAT_GRADUAL_DRAIN = 7;
    uint8 constant THREAT_NONCE_JUMP = 8;

    // ======================== Constants ========================

    /// @notice The Bybit cold wallet (Safe proxy)
    address constant BYBIT_COLD_WALLET = 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4;

    /// @notice Expected Safe singleton (masterCopy) address
    address constant EXPECTED_MASTER_COPY = 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;

    /// @notice Expected Safe threshold (number of required signers)
    ///         Bybit's cold wallet required 3 of N signers.
    uint256 constant EXPECTED_THRESHOLD = 3;

    /// @notice Tokens the attacker drained alongside ETH
    address constant STETH  = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    address constant METH   = 0xd5F7838F5C461fefF7FE49ea5ebaF7728bB0ADfa;
    address constant CMETH  = 0xe3C063B1BEe9de02eb28352b55D49D85514C67FF;

    /// @notice Balance drop threshold in basis points (500 = 5%)
    uint256 constant DROP_THRESHOLD_BPS = 500;

    /// @notice Gradual drain threshold in basis points (1500 = 15%)
    uint256 constant GRADUAL_DRAIN_THRESHOLD_BPS = 1500;

    /// @notice Maximum expected nonce increment between consecutive blocks
    uint256 constant MAX_NONCE_JUMP = 5;

    /// @notice Safe guard manager storage slot: keccak256("guard_manager.guard.address")
    uint256 constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @notice Module pagination: max pages to iterate (prevents infinite loops)
    uint256 constant MAX_MODULE_PAGES = 10;

    /// @notice Module pagination: modules per page
    uint256 constant MODULES_PER_PAGE = 10;

    // ======================== Snapshot Struct ========================

    struct Snapshot {
        // Implementation
        bool implementationValid;  // true if Safe functions respond normally
        address masterCopy;        // slot 0 direct read (address(0) if read fails)
        // Safe config
        uint256 threshold;         // Safe signing threshold (0 if implementation broken)
        uint256 ownerCount;        // Number of Safe owners (0 if implementation broken)
        bytes32 ownersHash;        // keccak256(abi.encode(getOwners()))
        uint256 nonce;             // Safe transaction nonce
        // Modules & guard
        uint256 moduleCount;       // Number of enabled modules
        bytes32 modulesHash;       // keccak256(abi.encode(modules)) — incremental across pages
        address guard;             // Transaction guard address
        // Balances
        uint256 ethBalance;
        uint256 stethBalance;
        uint256 methBalance;
        uint256 cmethBalance;
        uint256 aggregateBalance;  // raw sum of all balances (assumes ~1:1 ETH parity, not a true market value)
    }

    // ======================== collect() ========================

    function collect() external view returns (bytes memory) {
        // Probe the Safe implementation by calling Safe-specific functions.
        (
            bool implValid,
            uint256 threshold,
            uint256 ownerCount,
            bytes32 ownersHash,
            uint256 nonce
        ) = _probeSafeImplementation(BYBIT_COLD_WALLET);

        // Read masterCopy from slot 0 via getStorageAt
        address masterCopy = _readMasterCopy(BYBIT_COLD_WALLET);

        // Read modules (paginated — enumerates all pages)
        (uint256 moduleCount, bytes32 modulesHash) = _readModules(BYBIT_COLD_WALLET);

        // Read guard
        address guard = _readGuard(BYBIT_COLD_WALLET);

        // Read balances
        uint256 ethBal = BYBIT_COLD_WALLET.balance;
        uint256 stethBal = _safeBalanceOf(STETH, BYBIT_COLD_WALLET);
        uint256 methBal = _safeBalanceOf(METH, BYBIT_COLD_WALLET);
        uint256 cmethBal = _safeBalanceOf(CMETH, BYBIT_COLD_WALLET);

        uint256 total = ethBal + stethBal + methBal + cmethBal;

        return abi.encode(Snapshot({
            implementationValid: implValid,
            masterCopy: masterCopy,
            threshold: threshold,
            ownerCount: ownerCount,
            ownersHash: ownersHash,
            nonce: nonce,
            moduleCount: moduleCount,
            modulesHash: modulesHash,
            guard: guard,
            ethBalance: ethBal,
            stethBalance: stethBal,
            methBalance: methBal,
            cmethBalance: cmethBal,
            aggregateBalance: total
        }));
    }

    // ======================== shouldRespond() ========================

    /// @notice All return payloads are abi.encode(uint8 threatType, bytes details)
    ///         to match the responder's handleIncident(uint8,bytes) interface.
    function shouldRespond(
        bytes[] calldata data
    ) external pure returns (bool, bytes memory) {
        if (data.length < 2) return (false, "");
        if (data[0].length == 0 || data[1].length == 0) return (false, "");

        Snapshot memory current = abi.decode(data[0], (Snapshot));
        Snapshot memory previous = abi.decode(data[1], (Snapshot));

        // ---- Vector 1: Implementation integrity (functions revert) ----
        if (!current.implementationValid) {
            return (true, abi.encode(
                THREAT_IMPLEMENTATION_COMPROMISED,
                abi.encode(current.threshold, current.ownerCount)
            ));
        }

        // ---- Vector 2: Subtle masterCopy swap (functions still work) ----
        if (current.masterCopy != address(0) && current.masterCopy != EXPECTED_MASTER_COPY) {
            return (true, abi.encode(
                THREAT_MASTERCOPY_CHANGED,
                abi.encode(EXPECTED_MASTER_COPY, current.masterCopy)
            ));
        }

        // ---- Vector 3: Module additions ----
        if (previous.implementationValid && current.implementationValid) {
            if (current.moduleCount != previous.moduleCount
                || current.modulesHash != previous.modulesHash) {
                return (true, abi.encode(
                    THREAT_MODULES_CHANGED,
                    abi.encode(previous.moduleCount, current.moduleCount)
                ));
            }
        }

        // ---- Vector 4: Guard removal/change ----
        if (previous.implementationValid && current.implementationValid) {
            if (current.guard != previous.guard) {
                return (true, abi.encode(
                    THREAT_GUARD_CHANGED,
                    abi.encode(previous.guard, current.guard)
                ));
            }
        }

        // ---- Vector 5: Threshold/owner manipulation ----
        if (previous.implementationValid && current.implementationValid) {
            if (current.threshold != previous.threshold
                || current.ownerCount != previous.ownerCount
                || current.ownersHash != previous.ownersHash) {
                return (true, abi.encode(
                    THREAT_CONFIG_CHANGED,
                    abi.encode(
                        previous.threshold,
                        current.threshold,
                        previous.ownerCount,
                        current.ownerCount
                    )
                ));
            }
        }

        // ---- Vector 6: Catastrophic balance drain (>5% single block) ----
        if (previous.aggregateBalance > 0 && current.aggregateBalance < previous.aggregateBalance) {
            uint256 drop = previous.aggregateBalance - current.aggregateBalance;
            uint256 dropBps = (drop * 10000) / previous.aggregateBalance;

            if (dropBps >= DROP_THRESHOLD_BPS) {
                return (true, abi.encode(
                    THREAT_BALANCE_DRAIN,
                    abi.encode(previous.aggregateBalance, current.aggregateBalance, dropBps)
                ));
            }
        }

        // ---- Vector 7: Gradual drain (>15% across full window) ----
        if (data.length > 2) {
            bytes memory oldestData = data[data.length - 1];
            if (oldestData.length > 0) {
                Snapshot memory oldest = abi.decode(oldestData, (Snapshot));
                if (oldest.aggregateBalance > 0 && current.aggregateBalance < oldest.aggregateBalance) {
                    uint256 cumulativeDrop = oldest.aggregateBalance - current.aggregateBalance;
                    uint256 cumulativeDropBps = (cumulativeDrop * 10000) / oldest.aggregateBalance;

                    if (cumulativeDropBps >= GRADUAL_DRAIN_THRESHOLD_BPS) {
                        return (true, abi.encode(
                            THREAT_GRADUAL_DRAIN,
                            abi.encode(oldest.aggregateBalance, current.aggregateBalance, cumulativeDropBps)
                        ));
                    }
                }
            }
        }

        // ---- Vector 8: Nonce jump ----
        if (previous.implementationValid && current.implementationValid) {
            if (current.nonce > previous.nonce
                && (current.nonce - previous.nonce) > MAX_NONCE_JUMP) {
                return (true, abi.encode(
                    THREAT_NONCE_JUMP,
                    abi.encode(previous.nonce, current.nonce)
                ));
            }
        }

        return (false, "");
    }

    // ======================== Internal Helpers ========================

    /// @dev Probe the Safe implementation by calling Safe-specific functions.
    ///      Returns (isValid, threshold, ownerCount, ownersHash, nonce).
    function _probeSafeImplementation(address safe)
        internal view
        returns (bool, uint256, uint256, bytes32, uint256)
    {
        uint256 size;
        assembly { size := extcodesize(safe) }
        if (size == 0) return (false, 0, 0, bytes32(0), 0);

        // Try getThreshold
        uint256 threshold;
        try ISafe(safe).getThreshold() returns (uint256 t) {
            threshold = t;
        } catch {
            return (false, 0, 0, bytes32(0), 0);
        }

        // Try getOwners and hash the result
        uint256 ownerCount;
        bytes32 ownersHash;
        try ISafe(safe).getOwners() returns (address[] memory owners) {
            ownerCount = owners.length;
            ownersHash = keccak256(abi.encode(owners));
        } catch {
            return (false, 0, 0, bytes32(0), 0);
        }

        // Try nonce
        uint256 safeNonce;
        try ISafe(safe).nonce() returns (uint256 n) {
            safeNonce = n;
        } catch {
            return (false, 0, 0, bytes32(0), 0);
        }

        // Basic sanity: threshold should be > 0 and <= owner count
        if (threshold == 0 || threshold > ownerCount) {
            return (false, threshold, ownerCount, ownersHash, safeNonce);
        }

        return (true, threshold, ownerCount, ownersHash, safeNonce);
    }

    /// @dev Read masterCopy from storage slot 0 via Safe's getStorageAt.
    ///      Falls back to address(0) on failure (e.g., in fork context).
    function _readMasterCopy(address safe) internal view returns (address) {
        try ISafe(safe).getStorageAt(0, 1) returns (bytes memory result) {
            if (result.length >= 32) {
                return address(uint160(uint256(bytes32(result))));
            }
        } catch {}
        return address(0);
    }

    /// @dev Read all enabled modules by paginating through the linked list.
    ///      Uses incremental hashing to avoid dynamic array expansion.
    ///      Returns (totalCount, compositeHash) or (0, 0) on failure.
    function _readModules(address safe) internal view returns (uint256, bytes32) {
        address start = address(0x1); // Safe sentinel value
        uint256 totalCount = 0;
        bytes32 runningHash = bytes32(0);

        for (uint256 page = 0; page < MAX_MODULE_PAGES; page++) {
            try ISafe(safe).getModulesPaginated(start, MODULES_PER_PAGE)
                returns (address[] memory modules, address next)
            {
                totalCount += modules.length;
                // Incrementally hash each page into the running hash
                runningHash = keccak256(abi.encode(runningHash, modules));

                // next == sentinel (0x1) or zero means end of list
                if (next == address(0x1) || next == address(0) || modules.length == 0) {
                    break;
                }
                start = next;
            } catch {
                break;
            }
        }

        return (totalCount, runningHash);
    }

    /// @dev Read the guard address from the guard manager storage slot.
    ///      Returns address(0) on failure.
    function _readGuard(address safe) internal view returns (address) {
        try ISafe(safe).getStorageAt(GUARD_STORAGE_SLOT, 1)
            returns (bytes memory result)
        {
            if (result.length >= 32) {
                return address(uint160(uint256(bytes32(result))));
            }
        } catch {}
        return address(0);
    }

    /// @dev Safe ERC20 balanceOf — returns 0 on any failure
    function _safeBalanceOf(address token, address account) internal view returns (uint256) {
        uint256 size;
        assembly { size := extcodesize(token) }
        if (size == 0) return 0;

        try IERC20(token).balanceOf(account) returns (uint256 bal) {
            return bal;
        } catch {
            return 0;
        }
    }
}
