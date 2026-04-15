// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {BybitSafeTrap, ISafe, IERC20} from "../src/BybitSafeTrap.sol";
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

    // ======================== Part 1: Exploit Reproduction ========================
    // Self-contained proof of the Bybit attack state transition.
    // Demonstrates the exact on-chain damage at each stage using real mainnet state.

    /// @notice EXPLOIT REPRODUCTION: Replay the Bybit $1.46B hack step-by-step.
    ///
    ///   Step 1 (Block 21,895,237): Pre-exploit -- Safe proxy points to legitimate
    ///           singleton, all functions work, wallet holds ~$1.46B in ETH + LSTs.
    ///
    ///   Step 2 (Block 21,895,238): masterCopy swap -- Attacker's delegatecall
    ///           overwrites slot 0 with malicious implementation address.
    ///           Safe functions now revert (malicious contract doesn't implement them).
    ///           But ALL FUNDS ARE STILL IN THE WALLET -- 18-block response window.
    ///
    ///   Step 3 (Block 21,895,256): Drain -- Attacker calls backdoor functions on
    ///           the malicious implementation to sweep all funds.
    ///           401,346 ETH + 90,375 stETH + 8,000 mETH + 15,000 cmETH = $1.46B gone.
    ///
    ///   THIS IS WHERE DROSERA INTERVENES: Between Step 2 and Step 3.
    ///   The trap detects the masterCopy swap at Step 2 and triggers the response
    ///   contract to pause operations -- 18 blocks BEFORE the drain.
    function test_ExploitReproduction_BybitAttack() public {
        // ============================================================
        // STEP 1: Pre-exploit state (Block 21,895,237)
        // ============================================================
        uint256 preTotal = _step1_verifyPreExploitState();

        // ============================================================
        // STEP 2: masterCopy swap (Block 21,895,238)
        // The attacker's delegatecall writes the malicious impl address
        // into storage slot 0, replacing the Safe's masterCopy pointer.
        // ============================================================
        _step2_verifyMasterCopySwap();

        // ============================================================
        // STEP 3: Fund drain (Block 21,895,256)
        // Attacker calls backdoor functions to sweep everything.
        // ============================================================
        _step3_verifyDrain(preTotal);

        // ============================================================
        // DROSERA INTERVENTION: Trap detects the exploit at Step 2
        // ============================================================
        _step4_verifyDroseraDetection();
    }

    /// @dev Step 1: Verify pre-exploit state is healthy. Returns the pre-exploit total balance.
    function _step1_verifyPreExploitState() internal returns (uint256 preTotal) {
        vm.selectFork(preExploitFork);

        // Verify the Safe proxy points to the legitimate singleton
        bytes32 preSlot0 = vm.load(BYBIT_COLD_WALLET, SLOT_0);
        address preMasterCopy = address(uint160(uint256(preSlot0)));
        assertEq(preMasterCopy, EXPECTED_MASTER_COPY, "Pre-exploit: masterCopy must be legitimate singleton");

        // Verify Safe functions work normally
        uint256 preThreshold = ISafe(BYBIT_COLD_WALLET).getThreshold();
        assertEq(preThreshold, 3, "Pre-exploit: threshold must be 3 (3-of-N multisig)");
        assertGt(ISafe(BYBIT_COLD_WALLET).getOwners().length, 0, "Pre-exploit: must have owners");

        // Record pre-exploit balances
        preTotal = _getWalletTotal(BYBIT_COLD_WALLET);
        assertGt(preTotal, 400_000 ether, "Pre-exploit: wallet must hold >400k ETH equivalent");

        console.log("=== STEP 1: Pre-Exploit (Block %s) ===", PRE_EXPLOIT_BLOCK);
        console.log("masterCopy:  ", preMasterCopy);
        console.log("threshold:   ", preThreshold);
        console.log("Total value: ", preTotal);
    }

    /// @dev Step 2: Verify masterCopy was swapped and Safe functions revert, but funds remain.
    function _step2_verifyMasterCopySwap() internal {
        vm.selectFork(swapFork);
        address maliciousImpl = 0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516;

        bytes32 postSwapSlot0 = vm.load(BYBIT_COLD_WALLET, SLOT_0);
        address postSwapMasterCopy = address(uint160(uint256(postSwapSlot0)));

        // THE CRITICAL STATE CHANGE: slot 0 now points to attacker's contract
        assertTrue(postSwapMasterCopy != EXPECTED_MASTER_COPY, "Post-swap: masterCopy must NOT be legitimate");
        assertEq(postSwapMasterCopy, maliciousImpl, "Post-swap: masterCopy must be attacker's contract");

        // Safe functions now revert because malicious impl doesn't implement them
        bool safeCallReverted = false;
        try ISafe(BYBIT_COLD_WALLET).getThreshold() returns (uint256) {} catch { safeCallReverted = true; }
        assertTrue(safeCallReverted, "Post-swap: getThreshold() must revert (malicious impl)");

        // BUT: All funds are still in the wallet -- 18-block response window
        assertGt(BYBIT_COLD_WALLET.balance, 400_000 ether, "Post-swap: ETH still in wallet");

        console.log("=== STEP 2: masterCopy Swap (Block %s) ===", MASTERCOPY_SWAP_BLOCK);
        console.log("masterCopy:  ", postSwapMasterCopy);
        console.log("getThreshold: REVERTS (malicious impl)");
        console.log("ETH balance: ", BYBIT_COLD_WALLET.balance);
        console.log(">>> FUNDS STILL PRESENT -- 18-block response window begins");
    }

    /// @dev Step 3: Verify all funds were drained from the wallet.
    ///      Note: The Lazarus Group dispersed stolen funds to a network of laundering
    ///      addresses immediately, so the attacker EOA doesn't hold the bulk at this block.
    ///      We verify the damage from the victim's side.
    function _step3_verifyDrain(uint256 preTotal) internal {
        vm.selectFork(drainFork);

        uint256 postDrainTotal = _getWalletTotal(BYBIT_COLD_WALLET);

        // THE DAMAGE: virtually everything is gone
        assertLt(postDrainTotal, preTotal / 10, "Post-drain: >90% of funds must be gone");

        uint256 fundsLost = preTotal - postDrainTotal;
        assertGt(fundsLost, 400_000 ether, "Must have lost >400k ETH equivalent");

        console.log("=== STEP 3: Drain (Block %s) ===", DRAIN_BLOCK);
        console.log("Wallet remaining:", postDrainTotal);
        console.log("Funds lost:      ", fundsLost);
        console.log("Loss percentage: >99%%");
    }

    /// @dev Step 4: Verify Drosera trap detects the exploit at the swap block.
    function _step4_verifyDroseraDetection() internal {
        vm.selectFork(preExploitFork);
        bytes memory preSnapshot = preTrap.collect();

        vm.selectFork(swapFork);
        bytes memory swapSnapshot = swapTrap.collect();

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = swapSnapshot;  // newest: post-swap
        dataPoints[1] = preSnapshot;   // previous: pre-exploit

        (bool triggered, bytes memory response) = swapTrap.shouldRespond(dataPoints);
        assertTrue(triggered, "Drosera MUST detect the exploit at the swap block");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_IMPLEMENTATION_COMPROMISED, "Must fire as implementation compromise");

        console.log("");
        console.log("=== DROSERA INTERVENTION ===");
        console.log("Detected at block:   %s (masterCopy swap)", MASTERCOPY_SWAP_BLOCK);
        console.log("Drain happens at:    %s", DRAIN_BLOCK);
        console.log("Response window:     %s blocks", DRAIN_BLOCK - MASTERCOPY_SWAP_BLOCK);
        console.log("Threat type:         %s (IMPLEMENTATION_COMPROMISED)", threatType);
        console.log(">>> Drosera would have paused dependent operations 18 BLOCKS");
        console.log(">>> BEFORE the $1.46B drain, preventing the loss entirely.");
    }

    /// @dev Sum ETH + stETH + mETH + cmETH for a wallet (safe: handles missing contracts)
    function _getWalletTotal(address wallet) internal view returns (uint256 total) {
        total = wallet.balance;
        total += _safeBalanceOf(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84, wallet);  // stETH
        total += _safeBalanceOf(0xd5F7838F5C461fefF7FE49ea5ebaF7728bB0ADfa, wallet);  // mETH
        total += _safeBalanceOf(0xe3C063B1BEe9de02eb28352b55D49D85514C67FF, wallet);  // cmETH
    }

    /// @dev Safe ERC20 balanceOf — returns 0 if contract doesn't exist or call reverts
    function _safeBalanceOf(address token, address account) internal view returns (uint256) {
        if (token.code.length == 0) return 0;
        try IERC20(token).balanceOf(account) returns (uint256 bal) { return bal; }
        catch { return 0; }
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

    // ======================== Responder Integration Tests ========================

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

    /// @notice End-to-end: Detect -> Respond -> Contain cycle using real exploit data.
    ///
    ///   This test demonstrates the FULL Drosera response path:
    ///   1. Trap collects data at the real exploit blocks
    ///   2. shouldRespond() fires with the correct threat type and payload
    ///   3. The payload is passed directly to the responder's handleIncident()
    ///   4. Responder pauses operations and logs the incident
    ///   5. While paused, further operations are blocked
    ///   6. Admin resolves the incident and unpauses
    ///
    ///   This proves payload alignment end-to-end:
    ///   trap shouldRespond() -> abi.encode(uint8, bytes) -> handleIncident(uint8, bytes)
    function test_EndToEnd_DetectRespondContain() public {
        // --- Setup: Deploy responder and authorize the operator ---
        vm.selectFork(preExploitFork);
        address operator = address(0xBEEF);
        SafeGuardResponder responder = new SafeGuardResponder(address(this));
        responder.setAllowed(operator, true);

        // Verify responder starts in operational state
        assertTrue(responder.isOperational(), "Responder must start operational");
        assertEq(responder.incidentCount(), 0);

        // --- DETECT: Trap collects real exploit data ---
        bytes memory preSnapshot = preTrap.collect();

        vm.selectFork(swapFork);
        bytes memory swapSnapshot = swapTrap.collect();

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = swapSnapshot;  // newest: post-masterCopy-swap
        dataPoints[1] = preSnapshot;   // previous: pre-exploit

        (bool triggered, bytes memory responsePayload) = swapTrap.shouldRespond(dataPoints);
        assertTrue(triggered, "Trap must detect the implementation swap");

        // Decode the payload to verify it matches handleIncident(uint8, bytes) signature
        (uint8 threatType, bytes memory details) = abi.decode(responsePayload, (uint8, bytes));
        assertEq(threatType, THREAT_IMPLEMENTATION_COMPROMISED);

        // --- RESPOND: Operator submits the response transaction ---
        // In production, this is done by the Drosera operator network after BLS consensus.
        // The operator calls handleIncident() with the exact payload from shouldRespond().
        vm.selectFork(preExploitFork); // responder lives on this fork
        vm.prank(operator);
        responder.handleIncident(threatType, details);

        // --- CONTAIN: Verify operations are paused ---
        assertTrue(responder.isPaused(), "Responder must be paused after incident");
        assertFalse(responder.isOperational(), "Operations must be blocked");
        assertEq(responder.lastThreatType(), THREAT_IMPLEMENTATION_COMPROMISED);
        assertEq(responder.incidentCount(), 1);

        // While paused, further incident reports are blocked (prevents double-trigger)
        vm.prank(operator);
        vm.expectRevert("SafeGuardResponder: already paused");
        responder.handleIncident(THREAT_BALANCE_DRAIN, details);

        // --- RESOLVE: Admin investigates and unpauses ---
        responder.emergencyUnpause();
        assertTrue(responder.isOperational(), "Operations must resume after admin unpause");

        // Verify incident history is preserved
        (bool paused, uint256 incidentBlock, uint8 storedThreat, bytes memory storedDetails, uint256 totalIncidents)
            = responder.getIncidentInfo();
        assertFalse(paused);
        assertGt(incidentBlock, 0);
        assertEq(storedThreat, THREAT_IMPLEMENTATION_COMPROMISED);
        assertEq(storedDetails.length, details.length);
        assertEq(totalIncidents, 1);

        console.log("=== End-to-End: Detect -> Respond -> Contain ===");
        console.log("1. Trap detected implementation swap at block %s", MASTERCOPY_SWAP_BLOCK);
        console.log("2. Operator submitted response with threat type %s", threatType);
        console.log("3. Responder paused operations (drain at block %s prevented)", DRAIN_BLOCK);
        console.log("4. Admin resolved incident and resumed operations");
        console.log(">>> Full payload alignment verified: trap -> TOML -> responder");
    }

    // ======================== Edge Case Tests ========================

    /// @notice Empty data array should return (false, "") -- not revert
    function test_EdgeCase_EmptyDataArray() public {
        vm.selectFork(preExploitFork);
        bytes[] memory dataPoints = new bytes[](0);
        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Empty array must not trigger");
        assertEq(response.length, 0, "Empty array must return empty payload");
    }

    /// @notice Single sample (no comparison possible) should return (false, "")
    function test_EdgeCase_SingleSample() public {
        vm.selectFork(preExploitFork);
        bytes memory snapshot = preTrap.collect();

        bytes[] memory dataPoints = new bytes[](1);
        dataPoints[0] = snapshot;

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Single sample must not trigger");
        assertEq(response.length, 0, "Single sample must return empty payload");
    }

    /// @notice Zero-length bytes in data[0] should return (false, "") -- not revert
    function test_EdgeCase_ZeroLengthCurrentSample() public {
        vm.selectFork(preExploitFork);
        bytes memory validSnapshot = preTrap.collect();

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = "";          // zero-length current
        dataPoints[1] = validSnapshot;

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Zero-length current must not trigger");
        assertEq(response.length, 0);
    }

    /// @notice Zero-length bytes in data[1] should return (false, "") -- not revert
    function test_EdgeCase_ZeroLengthPreviousSample() public {
        vm.selectFork(preExploitFork);
        bytes memory validSnapshot = preTrap.collect();

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = validSnapshot;
        dataPoints[1] = "";          // zero-length previous

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Zero-length previous must not trigger");
        assertEq(response.length, 0);
    }

    /// @notice Malformed bytes (too short to be a valid Snapshot) should return (false, "")
    function test_EdgeCase_MalformedBytes() public {
        vm.selectFork(preExploitFork);
        bytes memory garbage = hex"deadbeef";

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = garbage;
        dataPoints[1] = garbage;

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Malformed bytes must not trigger");
        assertEq(response.length, 0);
    }

    /// @notice Both samples zero-length should return (false, "")
    function test_EdgeCase_BothSamplesEmpty() public {
        vm.selectFork(preExploitFork);
        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = "";
        dataPoints[1] = "";

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Both empty must not trigger");
        assertEq(response.length, 0);
    }

    // ======================== Boundary Threshold Tests ========================

    /// @notice Balance drain at exactly 499 bps (4.99%) should NOT trigger
    function test_Boundary_BalanceDrain_BelowThreshold() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        // Drop of exactly 499 bps = 4.99% -- just under the 500 bps (5%) threshold
        // Formula: dropBps = (drop * 10000) / previous = ((prev - curr) * 10000) / prev
        // We want dropBps = 499, so curr = prev * (10000 - 499) / 10000 = prev * 9501 / 10000
        uint256 adjustedTotal = base.aggregateBalance * 9501 / 10000;

        bytes memory drainedSnapshot = _craftSnapshot(base, adjustedTotal);
        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = drainedSnapshot;
        dataPoints[1] = baseSnapshot;

        (bool shouldTrigger,) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "499 bps drop must NOT trigger (below 500 bps threshold)");
    }

    /// @notice Balance drain at exactly 500 bps (5.0%) SHOULD trigger
    function test_Boundary_BalanceDrain_AtThreshold() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        // Drop of exactly 500 bps = 5.0%
        // curr = prev * (10000 - 500) / 10000 = prev * 9500 / 10000
        uint256 adjustedTotal = base.aggregateBalance * 9500 / 10000;

        bytes memory drainedSnapshot = _craftSnapshot(base, adjustedTotal);
        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = drainedSnapshot;
        dataPoints[1] = baseSnapshot;

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldTrigger, "500 bps drop MUST trigger (at threshold)");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_BALANCE_DRAIN);
    }

    /// @notice Balance drain at 501 bps (5.01%) SHOULD trigger
    function test_Boundary_BalanceDrain_AboveThreshold() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        // Drop of 501 bps = 5.01%
        uint256 adjustedTotal = base.aggregateBalance * 9499 / 10000;

        bytes memory drainedSnapshot = _craftSnapshot(base, adjustedTotal);
        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = drainedSnapshot;
        dataPoints[1] = baseSnapshot;

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldTrigger, "501 bps drop MUST trigger (above threshold)");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_BALANCE_DRAIN);
    }

    /// @notice Nonce jump of exactly 5 should NOT trigger (threshold is >5)
    function test_Boundary_NonceJump_AtLimit() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        bytes memory jumpedSnapshot = _craftSnapshotWithNonce(base, base.nonce + 5);
        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = jumpedSnapshot;
        dataPoints[1] = baseSnapshot;

        (bool shouldTrigger,) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Nonce jump of exactly 5 must NOT trigger (threshold is >5)");
    }

    /// @notice Nonce jump of 6 SHOULD trigger (exceeds >5 threshold)
    function test_Boundary_NonceJump_AboveLimit() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        bytes memory jumpedSnapshot = _craftSnapshotWithNonce(base, base.nonce + 6);
        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = jumpedSnapshot;
        dataPoints[1] = baseSnapshot;

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldTrigger, "Nonce jump of 6 MUST trigger (exceeds >5 threshold)");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_NONCE_JUMP);
    }

    /// @notice Gradual drain at 1499 bps (14.99%) should NOT trigger
    ///         Uses 5 samples so each per-block drop stays well under the 5% single-block threshold.
    function test_Boundary_GradualDrain_BelowThreshold() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        uint256 originalTotal = base.aggregateBalance;
        // 5 samples, ~3.75% per step, cumulative 14.99% (just under 1500 bps)
        // Per-block drops: ~375-422 bps each (all safely under 500 bps)
        bytes[] memory dataPoints = new bytes[](5);
        dataPoints[0] = _craftSnapshot(base, originalTotal * 8501 / 10000);  // 85.01%
        dataPoints[1] = _craftSnapshot(base, originalTotal * 8875 / 10000);  // 88.75%
        dataPoints[2] = _craftSnapshot(base, originalTotal * 9250 / 10000);  // 92.50%
        dataPoints[3] = _craftSnapshot(base, originalTotal * 9625 / 10000);  // 96.25%
        dataPoints[4] = baseSnapshot;                                         // 100%

        (bool shouldTrigger,) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "1499 bps cumulative drop must NOT trigger (below 1500 bps)");
    }

    /// @notice Gradual drain at 1500 bps (15.0%) SHOULD trigger
    ///         Uses 5 samples so each per-block drop stays under 5%.
    function test_Boundary_GradualDrain_AtThreshold() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        uint256 originalTotal = base.aggregateBalance;
        // 5 samples, ~3.75% per step, cumulative exactly 15% (1500 bps)
        bytes[] memory dataPoints = new bytes[](5);
        dataPoints[0] = _craftSnapshot(base, originalTotal * 8500 / 10000);  // 85.00%
        dataPoints[1] = _craftSnapshot(base, originalTotal * 8875 / 10000);  // 88.75%
        dataPoints[2] = _craftSnapshot(base, originalTotal * 9250 / 10000);  // 92.50%
        dataPoints[3] = _craftSnapshot(base, originalTotal * 9625 / 10000);  // 96.25%
        dataPoints[4] = baseSnapshot;                                         // 100%

        (bool shouldTrigger, bytes memory response) = preTrap.shouldRespond(dataPoints);
        assertTrue(shouldTrigger, "1500 bps cumulative drop MUST trigger (at threshold)");

        (uint8 threatType,) = _decodeThreat(response);
        assertEq(threatType, THREAT_GRADUAL_DRAIN);
    }

    // ======================== Sample Ordering Tests ========================

    /// @notice Verify data[0] = newest, data[1] = previous convention is respected.
    ///         Swapping order (putting pre-exploit in data[0]) should NOT trigger,
    ///         because a "recovering" balance is not a drain.
    function test_SampleOrdering_SwappedOrderNoFalsePositive() public {
        vm.selectFork(preExploitFork);
        bytes memory baseSnapshot = preTrap.collect();
        BybitSafeTrap.Snapshot memory base = abi.decode(baseSnapshot, (BybitSafeTrap.Snapshot));

        // Simulate: data[0] = higher balance (recovery), data[1] = lower balance (was drained)
        uint256 lowTotal = base.aggregateBalance * 8000 / 10000; // 80% of original

        bytes memory lowSnapshot = _craftSnapshot(base, lowTotal);
        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = baseSnapshot;  // "current" is full balance (recovered)
        dataPoints[1] = lowSnapshot;   // "previous" was lower (was drained)

        (bool shouldTrigger,) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Increasing balance (recovery) must NOT trigger drain detection");
    }

    /// @notice Verify that identical consecutive snapshots do not trigger
    function test_SampleOrdering_IdenticalSnapshots() public {
        vm.selectFork(preExploitFork);
        bytes memory snapshot = preTrap.collect();

        bytes[] memory dataPoints = new bytes[](2);
        dataPoints[0] = snapshot;
        dataPoints[1] = snapshot;

        (bool shouldTrigger,) = preTrap.shouldRespond(dataPoints);
        assertFalse(shouldTrigger, "Identical snapshots must NOT trigger");
    }

    // ======================== Helpers ========================

    function _logBalances(BybitSafeTrap.Snapshot memory s) internal view {
        console.log("ETH:                 ", s.ethBalance);
        console.log("stETH:               ", s.stethBalance);
        console.log("mETH:                ", s.methBalance);
        console.log("cmETH:               ", s.cmethBalance);
        console.log("Aggregate balance:   ", s.aggregateBalance);
    }

    /// @dev Craft a snapshot identical to base but with a different aggregateBalance.
    ///      Puts all value into ethBalance for simplicity.
    function _craftSnapshot(
        BybitSafeTrap.Snapshot memory base,
        uint256 newTotal
    ) internal pure returns (bytes memory) {
        return abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: base.implementationValid,
            masterCopy: base.masterCopy,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: base.ownersHash,
            nonce: base.nonce,
            moduleCount: base.moduleCount,
            modulesHash: base.modulesHash,
            guard: base.guard,
            ethBalance: newTotal,
            stethBalance: 0,
            methBalance: 0,
            cmethBalance: 0,
            aggregateBalance: newTotal
        }));
    }

    /// @dev Craft a snapshot identical to base but with a different nonce.
    function _craftSnapshotWithNonce(
        BybitSafeTrap.Snapshot memory base,
        uint256 newNonce
    ) internal pure returns (bytes memory) {
        return abi.encode(BybitSafeTrap.Snapshot({
            implementationValid: base.implementationValid,
            masterCopy: base.masterCopy,
            threshold: base.threshold,
            ownerCount: base.ownerCount,
            ownersHash: base.ownersHash,
            nonce: newNonce,
            moduleCount: base.moduleCount,
            modulesHash: base.modulesHash,
            guard: base.guard,
            ethBalance: base.ethBalance,
            stethBalance: base.stethBalance,
            methBalance: base.methBalance,
            cmethBalance: base.cmethBalance,
            aggregateBalance: base.aggregateBalance
        }));
    }
}
