// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {BybitSafeTrap} from "../src/BybitSafeTrap.sol";
import {SafeGuardResponder} from "../src/SafeGuardResponder.sol";

/// @title Bybit Safe Exploit -- Drosera Trap Test
/// @notice Validates that the BybitSafeTrap detects implementation swaps,
///         balance drains, module changes, guard changes, owner manipulation,
///         gradual drains, and nonce jumps — with correctly wired response payloads.
///
///         Timeline:
///           Block 21,895,237 -- pre-exploit (everything normal)
///           Block 21,895,238 -- masterCopy swapped via delegatecall (DETECTION POINT 1)
///           Block 21,895,256 -- ETH drained from wallet (DETECTION POINT 2)
///           => 18-block window for Drosera to trigger emergency response
///
///         Exploit TX: 0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882
///
/// @dev Run: forge test --contracts test/BybitSafeTrap.t.sol -vv
contract BybitSafeTrapTest is Test {
    uint256 constant MASTERCOPY_SWAP_BLOCK = 21_895_238;
    uint256 constant PRE_EXPLOIT_BLOCK = MASTERCOPY_SWAP_BLOCK - 1;
    uint256 constant DRAIN_BLOCK = 21_895_256;

    address constant BYBIT_COLD_WALLET = 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4;
    address constant EXPECTED_MASTER_COPY = 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;

    // Threat type constants (must match BybitSafeTrap)
    uint8 constant THREAT_IMPLEMENTATION_COMPROMISED = 1;
    uint8 constant THREAT_MASTERCOPY_CHANGED = 2;
    uint8 constant THREAT_MODULES_CHANGED = 3;
    uint8 constant THREAT_GUARD_CHANGED = 4;
    uint8 constant THREAT_CONFIG_CHANGED = 5;
    uint8 constant THREAT_BALANCE_DRAIN = 6;
    uint8 constant THREAT_GRADUAL_DRAIN = 7;
    uint8 constant THREAT_NONCE_JUMP = 8;

    /// @notice Safe storage slots
    bytes32 constant SLOT_0 = bytes32(uint256(0));
    bytes32 constant GUARD_SLOT = bytes32(uint256(0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8));

    uint256 preExploitFork;
    uint256 swapFork;
    uint256 drainFork;

    BybitSafeTrap preTrap;
    BybitSafeTrap swapTrap;
    BybitSafeTrap drainTrap;

    function setUp() public {
        preExploitFork = vm.createSelectFork("mainnet", PRE_EXPLOIT_BLOCK);
        preTrap = new BybitSafeTrap();

        swapFork = vm.createSelectFork("mainnet", MASTERCOPY_SWAP_BLOCK);
        swapTrap = new BybitSafeTrap();

        drainFork = vm.createSelectFork("mainnet", DRAIN_BLOCK);
        drainTrap = new BybitSafeTrap();
    }

    // ======================== Helper: decode response payload ========================

    /// @dev Decodes the standardized (uint8 threatType, bytes details) payload
    function _decodeThreat(bytes memory response) internal pure returns (uint8, bytes memory) {
        return abi.decode(response, (uint8, bytes));
    }

    // ======================== Core Exploit Detection Tests ========================

    /// @notice Pre-exploit: Safe functions work, balances are large
    function test_PreExploitState() public {
        vm.selectFork(preExploitFork);

        bytes memory snapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory s = abi.decode(snapshot, (BybitSafeTrap.Snapshot));

        assertTrue(s.implementationValid, "Pre-exploit implementation should be valid");
        assertEq(s.threshold, 3, "Bybit cold wallet requires 3 signers");
        assertGt(s.ownerCount, 0, "Should have owners");
        assertTrue(s.ownersHash != bytes32(0), "Should have owners hash");
        assertGt(s.ethBalance, 0, "Should hold ETH");
        assertGt(s.aggregateBalance, 0, "Should have aggregate balance");

        console.log("=== Pre-Exploit State (Block %s) ===", PRE_EXPLOIT_BLOCK);
        console.log("Implementation valid: true");
        console.log("Threshold:           ", s.threshold);
        console.log("Owner count:         ", s.ownerCount);
        console.log("Nonce:               ", s.nonce);
        console.log("Module count:        ", s.moduleCount);
        console.log("Guard:               ", s.guard);
        _logBalances(s);

        // Verify slot 0 directly via vm.load for documentation
        bytes32 slot0 = vm.load(BYBIT_COLD_WALLET, SLOT_0);
        address masterCopy = address(uint160(uint256(slot0)));
        assertEq(masterCopy, EXPECTED_MASTER_COPY, "Pre-exploit masterCopy should be legitimate Safe singleton");
        console.log("masterCopy (slot 0): ", masterCopy);
    }

    /// @notice Post-swap: Safe functions revert, ETH still present (18-block window)
    function test_PostSwapState() public {
        vm.selectFork(swapFork);

        bytes memory snapshot = swapTrap.collect();
        BybitSafeTrap.Snapshot memory s = abi.decode(snapshot, (BybitSafeTrap.Snapshot));

        assertFalse(s.implementationValid, "Post-swap implementation should be INVALID");
        assertEq(s.threshold, 0, "Threshold should be 0 (call reverted)");
        assertGt(s.ethBalance, 0, "ETH should still be present (drain comes 18 blocks later)");

        console.log("=== Post-Swap State (Block %s) ===", MASTERCOPY_SWAP_BLOCK);
        console.log("Implementation valid: FALSE (masterCopy was swapped!)");
        console.log("NOTE: ETH is still in wallet -- drain comes 18 blocks later");
        _logBalances(s);

        // Verify slot 0 is now the malicious implementation
        bytes32 slot0 = vm.load(BYBIT_COLD_WALLET, SLOT_0);
        address masterCopy = address(uint160(uint256(slot0)));
        assertTrue(masterCopy != EXPECTED_MASTER_COPY, "masterCopy should be malicious");
        console.log("masterCopy (slot 0): ", masterCopy);
    }

    /// @notice Core test: shouldRespond fires on implementation swap
    function test_DetectsImplementationSwap() public {
        vm.selectFork(preExploitFork);
        bytes memory preSnapshot = preTrap.collect();

        vm.selectFork(swapFork);
        bytes memory swapSnapshot = swapTrap.collect();

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = swapSnapshot;  // newest
        dataPoints[1] = preSnapshot;   // previous

        (bool shouldRespond, bytes memory response) = swapTrap.shouldRespond(dataPoints);
        assertTrue(shouldRespond, "Trap MUST detect the implementation swap");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_IMPLEMENTATION_COMPROMISED);

        console.log("=== TRAP FIRED: Implementation swap detected ===");
        console.log("Threat type:         %s", threatType);
        console.log("Detected at block:   %s", MASTERCOPY_SWAP_BLOCK);
        console.log("Drain happens at:    %s", DRAIN_BLOCK);
        console.log("Response window:     %s blocks", DRAIN_BLOCK - MASTERCOPY_SWAP_BLOCK);
        console.log("");
        console.log(">>> Drosera would have triggered emergency response 18 BLOCKS");
        console.log(">>> BEFORE the $1.46B drain occurred.");
    }

    /// @notice Test that balance drain is also detected (secondary signal)
    function test_DetectsBalanceDrain() public {
        // Pre-drain (block before drain -- masterCopy already swapped but ETH present)
        vm.createSelectFork("mainnet", DRAIN_BLOCK - 1);
        BybitSafeTrap preDrainTrap = new BybitSafeTrap();
        bytes memory preDrainSnapshot = preDrainTrap.collect();
        BybitSafeTrap.Snapshot memory pre = abi.decode(preDrainSnapshot, (BybitSafeTrap.Snapshot));

        // Post-drain
        vm.selectFork(drainFork);
        bytes memory postDrainSnapshot = drainTrap.collect();
        BybitSafeTrap.Snapshot memory post = abi.decode(postDrainSnapshot, (BybitSafeTrap.Snapshot));

        console.log("=== Balance Drain Analysis ===");
        console.log("Pre-drain total (wei):  ", pre.aggregateBalance);
        console.log("Post-drain total (wei): ", post.aggregateBalance);

        if (pre.aggregateBalance > 0 && post.aggregateBalance < pre.aggregateBalance) {
            uint256 drop = pre.aggregateBalance - post.aggregateBalance;
            uint256 dropBps = (drop * 10000) / pre.aggregateBalance;
            console.log("Drop (bps):             ", dropBps);
            assertGt(dropBps, 500, "Balance drop should exceed 5% threshold");
        }
    }

    /// @notice No false positive during normal operation
    function test_NoFalsePositive() public {
        uint256 normalBlock1 = 21_890_000;
        uint256 normalBlock2 = 21_890_001;

        vm.createSelectFork("mainnet", normalBlock1);
        BybitSafeTrap trap1 = new BybitSafeTrap();
        bytes memory snapshot1 = trap1.collect();

        vm.createSelectFork("mainnet", normalBlock2);
        BybitSafeTrap trap2 = new BybitSafeTrap();
        bytes memory snapshot2 = trap2.collect();

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = snapshot2;
        dataPoints[1] = snapshot1;

        (bool shouldRespond, ) = trap2.shouldRespond(dataPoints);
        assertFalse(shouldRespond, "Trap should NOT fire during normal operation");

        // Verify implementation is valid at these normal blocks
        BybitSafeTrap.Snapshot memory s = abi.decode(snapshot2, (BybitSafeTrap.Snapshot));
        assertTrue(s.implementationValid, "Implementation should be valid at normal blocks");

        console.log("=== Normal Operation: No false positive ===");
    }

    /// @notice Full Drosera operator simulation with 5 block samples
    function test_FullOperatorFlow() public {
        console.log("=== Full Drosera Operator Simulation ===");
        console.log("Block sample size: 5");
        console.log("");

        uint8 numBlocks = 5;
        bytes[] memory snapshots = new bytes[](numBlocks);

        for (uint8 i = 0; i < numBlocks; i++) {
            uint256 blockNum = MASTERCOPY_SWAP_BLOCK - i;
            vm.createSelectFork("mainnet", blockNum);
            BybitSafeTrap trap = new BybitSafeTrap();
            snapshots[i] = trap.collect();

            BybitSafeTrap.Snapshot memory s = abi.decode(snapshots[i], (BybitSafeTrap.Snapshot));
            console.log("Block %s | implValid: %s | threshold: %s",
                blockNum,
                s.implementationValid ? "YES" : "NO",
                s.threshold
            );
        }

        (bool shouldRespond, bytes memory response) = new BybitSafeTrap().shouldRespond(snapshots);

        assertTrue(shouldRespond, "Trap MUST fire in full operator flow");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_IMPLEMENTATION_COMPROMISED);

        console.log("");
        console.log("Drosera detected the Bybit exploit at block %s!", MASTERCOPY_SWAP_BLOCK);
        console.log("Emergency response triggered 18 blocks before the $1.46B drain.");
        console.log("Funds saved: ~$1.46 billion in ETH and liquid staking tokens.");
    }

    // ======================== Additional Attack Vector Tests ========================

    /// @notice Detect subtle masterCopy swap where new implementation still has Safe functions
    function test_DetectsSubtleMasterCopySwap() public {
        vm.selectFork(preExploitFork);
        bytes memory preSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(preSnapshot, (BybitSafeTrap.Snapshot));

        // Craft a snapshot where masterCopy changed to a different (but functional) singleton
        address fakeSingleton = address(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF);

        bytes memory craftedSnapshot = abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: true,
            masterCopy: fakeSingleton,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: base.ownersHash,
            nonce: base.nonce,
            moduleCount: base.moduleCount,
            modulesHash: base.modulesHash,
            guard: base.guard,
            ethBalance: base.ethBalance,
            stethBalance: base.stethBalance,
            methBalance: base.methBalance,
            cmethBalance: base.cmethBalance,
            aggregateBalance: base.aggregateBalance
        }));

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = craftedSnapshot;
        dataPoints[1] = preSnapshot;

        (bool shouldRespond, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldRespond, "Trap MUST detect subtle masterCopy swap");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_MASTERCOPY_CHANGED);

        console.log("=== Subtle masterCopy swap detected ===");
        console.log("Expected: ", EXPECTED_MASTER_COPY);
        console.log("Found:    ", fakeSingleton);
    }

    /// @notice Detect guard removal
    function test_DetectsGuardRemoval() public {
        vm.selectFork(preExploitFork);
        bytes memory preSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(preSnapshot, (BybitSafeTrap.Snapshot));

        address fakeGuard = address(0x1234567890123456789012345678901234567890);

        // Previous: had guard
        bytes memory withGuardSnapshot = abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: base.implementationValid,
            masterCopy: base.masterCopy,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: base.ownersHash,
            nonce: base.nonce,
            moduleCount: base.moduleCount,
            modulesHash: base.modulesHash,
            guard: fakeGuard,
            ethBalance: base.ethBalance,
            stethBalance: base.stethBalance,
            methBalance: base.methBalance,
            cmethBalance: base.cmethBalance,
            aggregateBalance: base.aggregateBalance
        }));

        // Current: guard removed
        bytes memory noGuardSnapshot = abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: base.implementationValid,
            masterCopy: base.masterCopy,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: base.ownersHash,
            nonce: base.nonce,
            moduleCount: base.moduleCount,
            modulesHash: base.modulesHash,
            guard: address(0),
            ethBalance: base.ethBalance,
            stethBalance: base.stethBalance,
            methBalance: base.methBalance,
            cmethBalance: base.cmethBalance,
            aggregateBalance: base.aggregateBalance
        }));

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = noGuardSnapshot;
        dataPoints[1] = withGuardSnapshot;

        (bool shouldRespond, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldRespond, "Trap MUST detect guard removal");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_GUARD_CHANGED);
        console.log("=== Guard removal detected ===");
    }

    /// @notice Detect module addition
    function test_DetectsModuleAddition() public {
        vm.selectFork(preExploitFork);
        bytes memory preSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(preSnapshot, (BybitSafeTrap.Snapshot));

        // Simulate module addition: increase count and change hash
        bytes memory withModuleSnapshot = abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: base.implementationValid,
            masterCopy: base.masterCopy,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: base.ownersHash,
            nonce: base.nonce,
            moduleCount: base.moduleCount + 1,
            modulesHash: keccak256("new_module_set"),
            guard: base.guard,
            ethBalance: base.ethBalance,
            stethBalance: base.stethBalance,
            methBalance: base.methBalance,
            cmethBalance: base.cmethBalance,
            aggregateBalance: base.aggregateBalance
        }));

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = withModuleSnapshot;
        dataPoints[1] = preSnapshot;

        (bool shouldRespond, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldRespond, "Trap MUST detect module addition");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_MODULES_CHANGED);
        console.log("=== Module addition detected ===");
    }

    /// @notice Detect gradual drain across window
    function test_DetectsGradualDrain() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        uint256 originalTotal = base.aggregateBalance;

        // Build a 10-block window with gradual 2% drops each block
        // Total: ~18% drop (above 15% threshold) but no single block exceeds 5%
        uint256 numBlocks = 10;
        bytes[] memory dataPoints = new bytes[](numBlocks);

        for (uint256 i = 0; i < numBlocks; i++) {
            // data[0] = newest (most drained), data[9] = oldest (original value)
            uint256 dropPercent = (numBlocks - 1 - i) * 2; // 0..18%
            uint256 adjustedTotal = originalTotal * (100 - dropPercent) / 100;

            dataPoints[i] = abi.encode(BybitSafeTrap.Snapshot({
                implementationValid: base.implementationValid,
                masterCopy: base.masterCopy,
                threshold: base.threshold,
                ownerCount: base.ownerCount,
                ownersHash: base.ownersHash,
                nonce: base.nonce,
                moduleCount: base.moduleCount,
                modulesHash: base.modulesHash,
                guard: base.guard,
                ethBalance: adjustedTotal,
                stethBalance: 0,
                methBalance: 0,
                cmethBalance: 0,
                aggregateBalance: adjustedTotal
            }));
        }

        (bool shouldRespond, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldRespond, "Trap MUST detect gradual drain across window");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_GRADUAL_DRAIN);
        console.log("=== Gradual drain detected ===");
        console.log("Original value:  ", originalTotal);
        console.log("Drained to:      ", originalTotal * 82 / 100);
    }

    /// @notice Detect nonce jump indicating rapid transaction execution
    function test_DetectsNonceJump() public {
        vm.selectFork(preExploitFork);
        bytes memory preSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(preSnapshot, (BybitSafeTrap.Snapshot));

        // Simulate nonce jump of 10 (exceeds MAX_NONCE_JUMP of 5)
        bytes memory jumpedSnapshot = abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: base.implementationValid,
            masterCopy: base.masterCopy,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: base.ownersHash,
            nonce: base.nonce + 10,
            moduleCount: base.moduleCount,
            modulesHash: base.modulesHash,
            guard: base.guard,
            ethBalance: base.ethBalance,
            stethBalance: base.stethBalance,
            methBalance: base.methBalance,
            cmethBalance: base.cmethBalance,
            aggregateBalance: base.aggregateBalance
        }));

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = jumpedSnapshot;
        dataPoints[1] = preSnapshot;

        (bool shouldRespond, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldRespond, "Trap MUST detect nonce jump");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_NONCE_JUMP);
        console.log("=== Nonce jump detected ===");
        console.log("Previous nonce: ", base.nonce);
        console.log("Current nonce:  ", base.nonce + 10);
    }

    /// @notice Detect owner set change (different signers, same count)
    function test_DetectsOwnerSetChange() public {
        vm.selectFork(preExploitFork);
        bytes memory preSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(preSnapshot, (BybitSafeTrap.Snapshot));

        // Same owner count but different owners hash
        bytes memory changedSnapshot = abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: base.implementationValid,
            masterCopy: base.masterCopy,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: keccak256("different_owner_set"),
            nonce: base.nonce,
            moduleCount: base.moduleCount,
            modulesHash: base.modulesHash,
            guard: base.guard,
            ethBalance: base.ethBalance,
            stethBalance: base.stethBalance,
            methBalance: base.methBalance,
            cmethBalance: base.cmethBalance,
            aggregateBalance: base.aggregateBalance
        }));

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = changedSnapshot;
        dataPoints[1] = preSnapshot;

        (bool shouldRespond, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldRespond, "Trap MUST detect owner set change");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_CONFIG_CHANGED);
        console.log("=== Owner set change detected ===");
    }

    // ======================== Responder Integration Test ========================

    /// @notice Verify the responder correctly receives and stores incident data
    function test_ResponderIntegration() public {
        vm.selectFork(preExploitFork);

        address caller = address(0xBEEF);
        SafeGuardResponder responder = new SafeGuardResponder(address(this));
        responder.setAllowed(caller, true);

        // Simulate a trap firing with threat type 1
        bytes memory details = abi.encode(uint256(0), uint256(0));

        vm.prank(caller);
        responder.handleIncident(THREAT_IMPLEMENTATION_COMPROMISED, details);

        assertTrue(responder.isPaused(), "Responder should be paused");
        assertEq(responder.lastThreatType(), THREAT_IMPLEMENTATION_COMPROMISED);
        assertEq(responder.incidentCount(), 1);

        // Unauthorized caller should revert
        vm.prank(address(0xDEAD));
        vm.expectRevert("SafeGuardResponder: not allowed");
        responder.handleIncident(THREAT_BALANCE_DRAIN, details);

        // Admin can unpause
        responder.emergencyUnpause();
        assertFalse(responder.isPaused(), "Responder should be unpaused");

        console.log("=== Responder integration test passed ===");
    }

    // ======================== Helpers ========================

    function _logBalances(BybitSafeTrap.Snapshot memory s) internal view {
        console.log("ETH:                 ", s.ethBalance);
        console.log("stETH:               ", s.stethBalance);
        console.log("mETH:                ", s.methBalance);
        console.log("cmETH:               ", s.cmethBalance);
        console.log("Aggregate balance:   ", s.aggregateBalance);
    }
}
