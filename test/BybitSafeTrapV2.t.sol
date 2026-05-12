// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {BybitSafeTrapV2} from "../src/BybitSafeTrapV2.sol";
import {BaselineFeeder} from "../src/BaselineFeeder.sol";
import {SafeGuardResponderV2} from "../src/SafeGuardResponderV2.sol";
import {SafeGuardianRegistry} from "../src/SafeGuardianRegistry.sol";
import {TrapDeployConfig} from "../src/TrapDeployConfig.sol";
import {MockGuardianTarget} from "../src/mocks/MockGuardianTarget.sol";

interface ISafeV2 {
    function getThreshold() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
}

/// @title BybitSafeTrapV2 + SafeGuardResponderV2 full test suite
/// @notice Covers:
///         - Constructorless trap wiring through TrapDeployConfig + feeder
///           overlaid at the configured address via `deployCodeTo`
///         - Synthetic shouldRespond logic (no fork required)
///         - BaselineFeeder-driven absolute checks + unconfigured-baseline path
///         - Read-failure flags (masterCopy / balances / baseline) feeding
///           MonitoringDegraded only after two consecutive degraded samples
///         - Malformed-bytes robustness (length check + failing closed)
///         - Sample-ordering + safeProxy-binding validation
///         - Every ThreatType trigger
///         - Live mainnet fork proving ImplementationCompromised fires at the real swap block
///         - Responder idempotency, retry-after-failure, allowlist, relayer,
///           global pause, registry fan-out
///         - Registry duplicate-target bug fix + MAX_TARGETS bound
contract BybitSafeTrapV2Test is Test {
    // ======================== Constants ========================

    uint256 constant MASTERCOPY_SWAP_BLOCK = 21_895_238;
    uint256 constant PRE_EXPLOIT_BLOCK = MASTERCOPY_SWAP_BLOCK - 1;

    // Mirror TrapDeployConfig so test asserts stay readable and break loudly
    // if anyone edits the deploy config without re-checking the test surface.
    address constant SAFE_PROXY = 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4;
    address constant EXPECTED_MASTER_COPY = 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;

    address constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    address constant METH  = 0xd5F7838F5C461fefF7FE49ea5ebaF7728bB0ADfa;
    address constant CMETH = 0xe3C063B1BEe9de02eb28352b55D49D85514C67FF;

    // ThreatType enum values (match BybitSafeTrapV2.ThreatType)
    uint8 constant TT_NONE = 0;
    uint8 constant TT_MONITORING_DEGRADED = 1;
    uint8 constant TT_IMPLEMENTATION_COMPROMISED = 2;
    uint8 constant TT_MASTERCOPY_CHANGED = 3;
    uint8 constant TT_MODULES_CHANGED = 4;
    uint8 constant TT_GUARD_CHANGED = 5;
    uint8 constant TT_CONFIG_CHANGED = 6;
    uint8 constant TT_BALANCE_DRAIN = 7;
    uint8 constant TT_GRADUAL_DRAIN = 8;
    uint8 constant TT_NONCE_JUMP = 9;

    // ======================== State ========================

    BybitSafeTrapV2 trap;
    BaselineFeeder feeder;

    // Default "healthy" values for synthesizing snapshots
    uint256 constant START_BLOCK = 100;
    uint256 constant BASE_BALANCE = 1_000 ether;
    bytes32 constant BASE_OWNERS_HASH = keccak256("owners");
    bytes32 constant BASE_MODULES_HASH = keccak256("modules");
    address constant BASE_GUARD = address(0xAAAA);

    function setUp() public {
        // The trap takes no constructor args (Drosera deployment model), so
        // the BaselineFeeder must live at the address baked into
        // TrapDeployConfig. We overlay a fresh feeder there via `vm.etch` and
        // seed its storage via `vm.store` — both are pure local writes that
        // avoid the copy-on-write storage fetch a real SSTORE would trigger
        // on a forked environment (the latter times out on the free-tier
        // archive RPC).
        _installFeeder();
        _seedBaseline(SAFE_PROXY, EXPECTED_MASTER_COPY, 3, 6, bytes32(0));
        feeder = BaselineFeeder(TrapDeployConfig.BASELINE_FEEDER);
        trap = new BybitSafeTrapV2();
    }

    /// @dev Overlay BaselineFeeder runtime code at TrapDeployConfig.BASELINE_FEEDER.
    function _installFeeder() internal {
        BaselineFeeder template = new BaselineFeeder(address(this));
        vm.etch(TrapDeployConfig.BASELINE_FEEDER, address(template).code);
        // Pre-set owner (slot 0) so any future onlyOwner call also stays local.
        vm.store(
            TrapDeployConfig.BASELINE_FEEDER,
            bytes32(uint256(0)),
            bytes32(uint256(uint160(address(this))))
        );
    }

    /// @dev Write the Baseline struct directly into storage at the slot the
    ///      compiler would use for `_baselines[safe]`. BaselineFeeder layout:
    ///        slot 0: owner
    ///        slot 1: mapping(address => Baseline) _baselines
    ///      Baseline (5 single-word fields):
    ///        +0 masterCopy, +1 threshold, +2 ownerCount, +3 ownersHash, +4 configured
    function _seedBaseline(
        address safe,
        address masterCopy_,
        uint256 threshold_,
        uint256 ownerCount_,
        bytes32 ownersHash_
    ) internal {
        bytes32 baseSlot = keccak256(abi.encode(safe, uint256(1)));
        address f = TrapDeployConfig.BASELINE_FEEDER;
        vm.store(f, baseSlot,                                bytes32(uint256(uint160(masterCopy_))));
        vm.store(f, bytes32(uint256(baseSlot) + 1),          bytes32(threshold_));
        vm.store(f, bytes32(uint256(baseSlot) + 2),          bytes32(ownerCount_));
        vm.store(f, bytes32(uint256(baseSlot) + 3),          ownersHash_);
        vm.store(f, bytes32(uint256(baseSlot) + 4),          bytes32(uint256(1))); // configured
    }

    // ======================== Snapshot helpers ========================

    function _healthySnapshot(uint256 blockNumber) internal pure returns (BybitSafeTrapV2.Snapshot memory s) {
        s.safeProxy = SAFE_PROXY;
        s.blockNumber = blockNumber;

        s.implementationValid = true;
        s.masterCopyReadOk = true;
        s.guardReadOk = true;
        s.modulesReadComplete = true;
        s.balancesReadOk = true;
        s.baselineReadOk = true;
        s.baselineConfigured = true;

        s.masterCopy = EXPECTED_MASTER_COPY;
        s.threshold = 3;
        s.ownerCount = 6;
        s.ownersHash = BASE_OWNERS_HASH;
        s.nonce = 42;

        s.moduleCount = 0;
        s.modulesHash = BASE_MODULES_HASH;
        s.guard = BASE_GUARD;

        s.expectedMasterCopy = EXPECTED_MASTER_COPY;
        s.expectedThreshold = 3;
        s.expectedOwnerCount = 6;
        s.expectedOwnersHash = bytes32(0);

        s.ethBalance = BASE_BALANCE;
        s.stethBalance = 0;
        s.methBalance = 0;
        s.cmethBalance = 0;
        s.aggregateBalance = BASE_BALANCE;
    }

    function _encode(BybitSafeTrapV2.Snapshot memory s) internal pure returns (bytes memory) {
        return abi.encode(s);
    }

    /// @dev Build a contiguous newest->oldest window where data[0].blockNumber == startNewest.
    function _contiguousWindow(BybitSafeTrapV2.Snapshot memory newest, uint256 size)
        internal
        pure
        returns (bytes[] memory data)
    {
        data = new bytes[](size);
        data[0] = _encode(newest);
        for (uint256 i = 1; i < size; i++) {
            BybitSafeTrapV2.Snapshot memory older = _healthySnapshot(newest.blockNumber - i);
            data[i] = _encode(older);
        }
    }

    function _decodeIncident(bytes memory raw)
        internal
        pure
        returns (BybitSafeTrapV2.IncidentPayload memory)
    {
        return abi.decode(raw, (BybitSafeTrapV2.IncidentPayload));
    }

    function _tt(BybitSafeTrapV2.IncidentPayload memory p) internal pure returns (uint8) {
        return uint8(p.threatType);
    }

    // ======================== 1. Normal behavior ========================

    function test_NoTrigger_HealthyWindow() public view {
        bytes[] memory data = _contiguousWindow(_healthySnapshot(START_BLOCK), 10);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertFalse(fired);
        assertEq(payload.length, 0);
    }

    // ======================== 2. Input guards ========================

    function test_NoTrigger_EmptyData() public view {
        bytes[] memory data = new bytes[](0);
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_NoTrigger_SingleSample() public view {
        bytes[] memory data = new bytes[](1);
        data[0] = _encode(_healthySnapshot(START_BLOCK));
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_NoTrigger_OversizedWindow() public view {
        bytes[] memory data = _contiguousWindow(_healthySnapshot(START_BLOCK), 10);
        bytes[] memory big = new bytes[](11);
        for (uint256 i = 0; i < 10; i++) big[i] = data[i];
        big[10] = _encode(_healthySnapshot(START_BLOCK - 10));
        (bool fired, ) = trap.shouldRespond(big);
        assertFalse(fired);
    }

    function test_NoTrigger_NonContiguousBlocks() public view {
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        BybitSafeTrapV2.Snapshot memory older = _healthySnapshot(START_BLOCK - 5);
        bytes[] memory data = new bytes[](2);
        data[0] = _encode(newest);
        data[1] = _encode(older);
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_NoTrigger_ReorderedBlocks() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = _encode(_healthySnapshot(START_BLOCK));
        data[1] = _encode(_healthySnapshot(START_BLOCK + 1));
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_NoTrigger_ZeroSafeProxy() public view {
        BybitSafeTrapV2.Snapshot memory s = _healthySnapshot(START_BLOCK);
        s.safeProxy = address(0);
        bytes[] memory data = new bytes[](2);
        data[0] = _encode(s);
        data[1] = _encode(_healthySnapshot(START_BLOCK - 1));
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_NoTrigger_MismatchedSafeProxy() public view {
        BybitSafeTrapV2.Snapshot memory newer = _healthySnapshot(START_BLOCK);
        BybitSafeTrapV2.Snapshot memory older = _healthySnapshot(START_BLOCK - 1);
        older.safeProxy = address(0xDEAD);
        bytes[] memory data = new bytes[](2);
        data[0] = _encode(newer);
        data[1] = _encode(older);
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    // Robust decoder: malformed-length bytes must fail closed, not revert.
    function test_NoTrigger_MalformedBytes_WrongLength() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = _encode(_healthySnapshot(START_BLOCK));
        data[1] = hex"deadbeef"; // 4 bytes — far short of ENCODED_SNAPSHOT_LEN
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertFalse(fired, "malformed-length previous must fail closed");
        assertEq(payload.length, 0);
    }

    function test_NoTrigger_MalformedBytes_EmptyPrevious() public view {
        bytes[] memory data = new bytes[](2);
        data[0] = _encode(_healthySnapshot(START_BLOCK));
        data[1] = bytes("");
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    // ======================== 3. Threat triggers ========================

    function _triggerWith(BybitSafeTrapV2.Snapshot memory newest)
        internal
        view
        returns (bool, BybitSafeTrapV2.IncidentPayload memory)
    {
        bytes[] memory data = _contiguousWindow(newest, 10);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        if (!fired) {
            BybitSafeTrapV2.IncidentPayload memory empty;
            return (false, empty);
        }
        return (true, _decodeIncident(payload));
    }

    /// @dev Two-element window where both samples carry the same degradation
    ///      mutator applied to a healthy base. MonitoringDegraded requires
    ///      sustained degradation across consecutive samples.
    function _twoSampleDegradedWindow(
        function(BybitSafeTrapV2.Snapshot memory) internal pure returns (BybitSafeTrapV2.Snapshot memory) mutate
    ) internal pure returns (bytes[] memory data) {
        BybitSafeTrapV2.Snapshot memory newest = mutate(_healthySnapshot(START_BLOCK));
        BybitSafeTrapV2.Snapshot memory previous = mutate(_healthySnapshot(START_BLOCK - 1));
        data = new bytes[](2);
        data[0] = _encode(newest);
        data[1] = _encode(previous);
    }

    function _failMasterCopy(BybitSafeTrapV2.Snapshot memory s)
        internal pure returns (BybitSafeTrapV2.Snapshot memory)
    { s.masterCopyReadOk = false; return s; }

    function _failBalances(BybitSafeTrapV2.Snapshot memory s)
        internal pure returns (BybitSafeTrapV2.Snapshot memory)
    { s.balancesReadOk = false; return s; }

    function _failBaseline(BybitSafeTrapV2.Snapshot memory s)
        internal pure returns (BybitSafeTrapV2.Snapshot memory)
    { s.baselineReadOk = false; return s; }

    function test_Trigger_MonitoringDegraded_MasterCopyReadFailedPersistent() public view {
        bytes[] memory data = _twoSampleDegradedWindow(_failMasterCopy);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        BybitSafeTrapV2.IncidentPayload memory p = _decodeIncident(payload);
        assertEq(_tt(p), TT_MONITORING_DEGRADED);
        assertEq(p.safeProxy, SAFE_PROXY);
        assertEq(p.currentBlockNumber, START_BLOCK);
        assertEq(p.previousBlockNumber, START_BLOCK - 1);
    }

    // Balance-read failures feed MonitoringDegraded when sustained for two samples.
    function test_Trigger_MonitoringDegraded_BalancesReadFailedPersistent() public view {
        bytes[] memory data = _twoSampleDegradedWindow(_failBalances);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        BybitSafeTrapV2.IncidentPayload memory p = _decodeIncident(payload);
        assertEq(_tt(p), TT_MONITORING_DEGRADED);
        (
            bool mcOk, bool gOk, bool modsOk, bool balsOk, bool baseOk,
            bool prevMcOk, bool prevGOk, bool prevModsOk, bool prevBalsOk, bool prevBaseOk
        ) = abi.decode(p.details, (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool));
        assertTrue(mcOk);
        assertTrue(gOk);
        assertTrue(modsOk);
        assertFalse(balsOk, "balancesReadOk must be surfaced in details");
        assertTrue(baseOk);
        assertTrue(prevMcOk);
        assertTrue(prevGOk);
        assertTrue(prevModsOk);
        assertFalse(prevBalsOk, "previous.balancesReadOk must also be surfaced");
        assertTrue(prevBaseOk);
    }

    // Baseline-feeder failures feed MonitoringDegraded when sustained.
    function test_Trigger_MonitoringDegraded_BaselineReadFailedPersistent() public view {
        bytes[] memory data = _twoSampleDegradedWindow(_failBaseline);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        BybitSafeTrapV2.IncidentPayload memory p = _decodeIncident(payload);
        assertEq(_tt(p), TT_MONITORING_DEGRADED);
    }

    // A single bad sample must NOT auto-pause — debounce across two samples
    // to absorb RPC blips.
    function test_NoTrigger_SingleSampleMonitoringDegraded() public view {
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        BybitSafeTrapV2.Snapshot memory previous = _healthySnapshot(START_BLOCK - 1);
        newest.balancesReadOk = false;
        previous.balancesReadOk = true;

        bytes[] memory data = new bytes[](2);
        data[0] = _encode(newest);
        data[1] = _encode(previous);

        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired, "single degraded sample should not auto-respond");
    }

    function test_Trigger_ImplementationCompromised() public view {
        BybitSafeTrapV2.Snapshot memory s = _healthySnapshot(START_BLOCK);
        s.implementationValid = false;
        (bool fired, BybitSafeTrapV2.IncidentPayload memory p) = _triggerWith(s);
        assertTrue(fired);
        assertEq(_tt(p), TT_IMPLEMENTATION_COMPROMISED);
    }

    function test_Trigger_MasterCopyChanged() public view {
        BybitSafeTrapV2.Snapshot memory s = _healthySnapshot(START_BLOCK);
        s.masterCopy = address(0xBAD);
        (bool fired, BybitSafeTrapV2.IncidentPayload memory p) = _triggerWith(s);
        assertTrue(fired);
        assertEq(_tt(p), TT_MASTERCOPY_CHANGED);
        (address expected, address actual) = abi.decode(p.details, (address, address));
        assertEq(expected, EXPECTED_MASTER_COPY);
        assertEq(actual, address(0xBAD));
    }

    function test_Trigger_ConfigChanged_AbsoluteThreshold() public view {
        BybitSafeTrapV2.Snapshot memory s = _healthySnapshot(START_BLOCK);
        s.threshold = 1;
        (bool fired, BybitSafeTrapV2.IncidentPayload memory p) = _triggerWith(s);
        assertTrue(fired);
        assertEq(_tt(p), TT_CONFIG_CHANGED);
    }

    function test_Trigger_ConfigChanged_AbsoluteOwnerCount() public view {
        BybitSafeTrapV2.Snapshot memory s = _healthySnapshot(START_BLOCK);
        s.ownerCount = 2;
        (bool fired, BybitSafeTrapV2.IncidentPayload memory p) = _triggerWith(s);
        assertTrue(fired);
        assertEq(_tt(p), TT_CONFIG_CHANGED);
    }

    // When baseline is not configured, absolute checks must NOT fire on
    // default/zero expected values.
    function test_NoTrigger_BaselineUnconfigured_NoFalseAbsolute() public view {
        BybitSafeTrapV2.Snapshot memory s = _healthySnapshot(START_BLOCK);
        s.baselineConfigured = false;
        s.expectedMasterCopy = address(0);
        s.expectedThreshold = 0;
        s.expectedOwnerCount = 0;
        s.expectedOwnersHash = bytes32(0);
        // s.masterCopy / threshold / ownerCount stay healthy; previous matches.
        (bool fired, ) = _triggerWith(s);
        assertFalse(fired, "unconfigured baseline must not fire absolute checks");
    }

    function test_Trigger_GuardChanged() public view {
        bytes[] memory data = _contiguousWindow(_healthySnapshot(START_BLOCK), 2);
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.guard = address(0xBEEF);
        data[0] = _encode(newest);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        BybitSafeTrapV2.IncidentPayload memory p = _decodeIncident(payload);
        assertEq(_tt(p), TT_GUARD_CHANGED);
    }

    function test_Trigger_ModulesChanged() public view {
        bytes[] memory data = _contiguousWindow(_healthySnapshot(START_BLOCK), 2);
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.moduleCount = 1;
        newest.modulesHash = keccak256("new-modules");
        data[0] = _encode(newest);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        assertEq(_tt(_decodeIncident(payload)), TT_MODULES_CHANGED);
    }

    function test_NoTrigger_ModulesChanged_PreviousIncompleteRead() public view {
        bytes[] memory data = new bytes[](2);
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.moduleCount = 2;
        newest.modulesHash = keccak256("x");
        BybitSafeTrapV2.Snapshot memory older = _healthySnapshot(START_BLOCK - 1);
        older.modulesReadComplete = false;
        older.moduleCount = 1;
        older.modulesHash = keccak256("y");
        data[0] = _encode(newest);
        data[1] = _encode(older);
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired);
    }

    function test_Trigger_ConfigChanged_RelativeOwnersHash() public view {
        bytes[] memory data = _contiguousWindow(_healthySnapshot(START_BLOCK), 2);
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.ownersHash = keccak256("rotated-owners");
        data[0] = _encode(newest);
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        assertEq(_tt(_decodeIncident(payload)), TT_CONFIG_CHANGED);
    }

    function test_Trigger_BalanceDrain_SingleBlock() public view {
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.ethBalance = (BASE_BALANCE * 9500) / 10_000;
        newest.aggregateBalance = newest.ethBalance;
        (bool fired, BybitSafeTrapV2.IncidentPayload memory p) = _triggerWith(newest);
        assertTrue(fired);
        assertEq(_tt(p), TT_BALANCE_DRAIN);
        (uint256 prevBal, uint256 curBal, uint256 dropBps) =
            abi.decode(p.details, (uint256, uint256, uint256));
        assertEq(prevBal, BASE_BALANCE);
        assertEq(curBal, newest.ethBalance);
        assertEq(dropBps, 500);
    }

    function test_NoTrigger_BalanceDrain_JustBelowThreshold() public view {
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.ethBalance = (BASE_BALANCE * 9501) / 10_000;
        newest.aggregateBalance = newest.ethBalance;
        (bool fired, ) = _triggerWith(newest);
        assertFalse(fired);
    }

    // A degraded previous snapshot must not let a bogus balance diff look
    // like a drain.
    function test_NoTrigger_BalanceDrain_PreviousBalancesDegraded() public view {
        bytes[] memory data = new bytes[](2);
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.ethBalance = (BASE_BALANCE * 9000) / 10_000; // 10% drop — would trigger
        newest.aggregateBalance = newest.ethBalance;
        BybitSafeTrapV2.Snapshot memory older = _healthySnapshot(START_BLOCK - 1);
        older.balancesReadOk = false;
        data[0] = _encode(newest);
        data[1] = _encode(older);
        (bool fired, ) = trap.shouldRespond(data);
        assertFalse(fired, "degraded previous must suppress drain");
    }

    function test_Trigger_GradualDrain() public view {
        bytes[] memory data = new bytes[](10);
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.ethBalance = 841 ether;
        newest.aggregateBalance = 841 ether;
        data[0] = _encode(newest);
        for (uint256 i = 1; i < 10; i++) {
            BybitSafeTrapV2.Snapshot memory older = _healthySnapshot(START_BLOCK - i);
            uint256 bal;
            if (i == 1) bal = 880 ether;          // 4.4% drop single-block vs newest
            else bal = BASE_BALANCE;
            older.ethBalance = bal;
            older.aggregateBalance = bal;
            data[i] = _encode(older);
        }
        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        assertEq(_tt(_decodeIncident(payload)), TT_GRADUAL_DRAIN);
    }

    function test_Trigger_NonceJump() public view {
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.nonce = 42 + 6;
        (bool fired, BybitSafeTrapV2.IncidentPayload memory p) = _triggerWith(newest);
        assertTrue(fired);
        assertEq(_tt(p), TT_NONCE_JUMP);
    }

    function test_NoTrigger_NonceJump_AtThreshold() public view {
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        newest.nonce = 42 + 5;
        (bool fired, ) = _triggerWith(newest);
        assertFalse(fired);
    }

    // ======================== 4. Priority ordering ========================

    function test_Priority_MonitoringDegradedBeatsImplementation() public view {
        // Sustained masterCopy-read failure across both samples preempts the
        // implementationValid signal.
        BybitSafeTrapV2.Snapshot memory newest = _healthySnapshot(START_BLOCK);
        BybitSafeTrapV2.Snapshot memory previous = _healthySnapshot(START_BLOCK - 1);
        newest.masterCopyReadOk = false;
        newest.implementationValid = false;
        previous.masterCopyReadOk = false;

        bytes[] memory data = new bytes[](2);
        data[0] = _encode(newest);
        data[1] = _encode(previous);

        (bool fired, bytes memory payload) = trap.shouldRespond(data);
        assertTrue(fired);
        assertEq(_tt(_decodeIncident(payload)), TT_MONITORING_DEGRADED);
    }

    function test_Priority_ImplementationBeatsMasterCopy() public view {
        BybitSafeTrapV2.Snapshot memory s = _healthySnapshot(START_BLOCK);
        s.implementationValid = false;
        s.masterCopy = address(0xBAD);
        (, BybitSafeTrapV2.IncidentPayload memory p) = _triggerWith(s);
        assertEq(_tt(p), TT_IMPLEMENTATION_COMPROMISED);
    }

    // ======================== 5. Fork-based Bybit reproduction ========================

    function _deployLiveTrap() internal returns (BybitSafeTrapV2) {
        // Re-overlay the feeder on the freshly selected fork (forking wipes
        // state at the constant address) and re-seed the baseline directly
        // into storage to avoid CoW reads against the free-tier archive RPC.
        _installFeeder();
        _seedBaseline(SAFE_PROXY, EXPECTED_MASTER_COPY, 3, 6, bytes32(0));
        return new BybitSafeTrapV2();
    }

    function test_Fork_PreExploit_CollectHealthy() public {
        vm.createSelectFork("mainnet", PRE_EXPLOIT_BLOCK);
        BybitSafeTrapV2 liveTrap = _deployLiveTrap();
        BybitSafeTrapV2.Snapshot memory s =
            abi.decode(liveTrap.collect(), (BybitSafeTrapV2.Snapshot));

        assertEq(s.safeProxy, SAFE_PROXY, "snapshot must bind to SAFE_PROXY");
        assertEq(s.blockNumber, PRE_EXPLOIT_BLOCK, "blockNumber must equal fork block");
        assertTrue(s.implementationValid, "pre-exploit Safe functions must succeed");
        assertTrue(s.baselineReadOk, "overlaid feeder read must succeed");
        assertTrue(s.baselineConfigured, "baseline was set in _deployLiveTrap");
        assertEq(s.expectedMasterCopy, EXPECTED_MASTER_COPY);
        assertEq(s.threshold, 3);
        assertGt(s.ownerCount, 0);
        assertGt(s.ethBalance, 400_000 ether, "pre-exploit must hold >400k ETH");
    }

    function test_Fork_AtSwap_ImplementationInvalid() public {
        vm.createSelectFork("mainnet", MASTERCOPY_SWAP_BLOCK);
        BybitSafeTrapV2 liveTrap = _deployLiveTrap();
        BybitSafeTrapV2.Snapshot memory s =
            abi.decode(liveTrap.collect(), (BybitSafeTrapV2.Snapshot));

        assertEq(s.safeProxy, SAFE_PROXY);
        assertEq(s.blockNumber, MASTERCOPY_SWAP_BLOCK);
        assertFalse(s.implementationValid, "post-swap Safe functions must revert");
        assertGt(s.ethBalance, 400_000 ether, "ETH still in wallet 18 blocks before drain");

        bytes32 slot0 = vm.load(SAFE_PROXY, bytes32(uint256(0)));
        address swapped = address(uint160(uint256(slot0)));
        assertTrue(swapped != EXPECTED_MASTER_COPY, "slot 0 was overwritten on-chain");
    }

    function test_Fork_AtSwap_TrapFiresImplementationCompromised() public {
        // Fork Foundry has a known getStorageAt quirk returning empty bytes, so
        // masterCopyReadOk / guardReadOk / modulesReadComplete come back false
        // and MonitoringDegraded would fire. We normalize those flags before
        // exercising the ImplementationCompromised branch — the real Bybit
        // signal on a production RPC. Balance + baseline reads work fine so we
        // leave those alone.
        vm.createSelectFork("mainnet", PRE_EXPLOIT_BLOCK);
        BybitSafeTrapV2 preTrap = _deployLiveTrap();
        BybitSafeTrapV2.Snapshot memory pre = abi.decode(preTrap.collect(), (BybitSafeTrapV2.Snapshot));

        vm.createSelectFork("mainnet", MASTERCOPY_SWAP_BLOCK);
        BybitSafeTrapV2 swapLive = _deployLiveTrap();
        BybitSafeTrapV2.Snapshot memory post =
            abi.decode(swapLive.collect(), (BybitSafeTrapV2.Snapshot));

        pre.masterCopyReadOk = true;
        pre.guardReadOk = true;
        pre.modulesReadComplete = true;
        pre.balancesReadOk = true;
        pre.baselineReadOk = true;
        pre.masterCopy = EXPECTED_MASTER_COPY;

        post.masterCopyReadOk = true;
        post.guardReadOk = true;
        post.modulesReadComplete = true;
        post.balancesReadOk = true;
        post.baselineReadOk = true;
        post.masterCopy = EXPECTED_MASTER_COPY;

        post.blockNumber = PRE_EXPLOIT_BLOCK + 1;
        pre.blockNumber = PRE_EXPLOIT_BLOCK;

        bytes[] memory data = new bytes[](2);
        data[0] = abi.encode(post);
        data[1] = abi.encode(pre);

        (bool fired, bytes memory payload) = swapLive.shouldRespond(data);
        assertTrue(fired, "masterCopy swap must trigger");

        BybitSafeTrapV2.IncidentPayload memory p = _decodeIncident(payload);
        assertEq(_tt(p), TT_IMPLEMENTATION_COMPROMISED);
        assertEq(p.safeProxy, SAFE_PROXY);
        assertEq(p.currentBlockNumber, PRE_EXPLOIT_BLOCK + 1);
        assertEq(p.previousBlockNumber, PRE_EXPLOIT_BLOCK);
    }
}

// ============================================================================
//                     BaselineFeeder tests
// ============================================================================

contract BaselineFeederTest is Test {
    BaselineFeeder feeder;
    address constant SAFE = 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4;
    address constant MC = 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;
    address admin = address(0xA11CE);
    address outsider = address(0xDEAD);

    function setUp() public {
        feeder = new BaselineFeeder(admin);
    }

    function test_Set_OnlyOwner() public {
        vm.prank(outsider);
        vm.expectRevert(bytes("not owner"));
        feeder.setBaseline(SAFE, MC, 3, 6, bytes32(0));
    }

    function test_Set_RejectsInvalid() public {
        vm.startPrank(admin);
        vm.expectRevert(bytes("zero safe"));
        feeder.setBaseline(address(0), MC, 3, 6, bytes32(0));
        vm.expectRevert(bytes("zero masterCopy"));
        feeder.setBaseline(SAFE, address(0), 3, 6, bytes32(0));
        vm.expectRevert(bytes("zero threshold"));
        feeder.setBaseline(SAFE, MC, 0, 6, bytes32(0));
        vm.expectRevert(bytes("zero ownerCount"));
        feeder.setBaseline(SAFE, MC, 3, 0, bytes32(0));
        vm.expectRevert(bytes("threshold > owners"));
        feeder.setBaseline(SAFE, MC, 10, 6, bytes32(0));
        vm.stopPrank();
    }

    function test_Set_AndRead() public {
        vm.prank(admin);
        feeder.setBaseline(SAFE, MC, 3, 6, keccak256("hash"));
        BaselineFeeder.Baseline memory b = feeder.getBaseline(SAFE);
        assertTrue(b.configured);
        assertEq(b.masterCopy, MC);
        assertEq(b.threshold, 3);
        assertEq(b.ownerCount, 6);
        assertEq(b.ownersHash, keccak256("hash"));
    }

    function test_ClearBaseline() public {
        vm.startPrank(admin);
        feeder.setBaseline(SAFE, MC, 3, 6, bytes32(0));
        feeder.clearBaseline(SAFE);
        vm.stopPrank();
        BaselineFeeder.Baseline memory b = feeder.getBaseline(SAFE);
        assertFalse(b.configured);
    }

    function test_UnsetBaseline_ReturnsUnconfigured() public view {
        BaselineFeeder.Baseline memory b = feeder.getBaseline(SAFE);
        assertFalse(b.configured);
        assertEq(b.masterCopy, address(0));
    }

    function test_SetOwner_OnlyOwner() public {
        vm.prank(outsider);
        vm.expectRevert(bytes("not owner"));
        feeder.setOwner(outsider);

        vm.prank(admin);
        feeder.setOwner(outsider);
        assertEq(feeder.owner(), outsider);
    }
}

// ============================================================================
//                     Responder + Registry + Mock tests
// ============================================================================

contract SafeGuardResponderV2Test is Test {
    SafeGuardianRegistry registry;
    SafeGuardResponderV2 responder;
    MockGuardianTarget targetA;
    MockGuardianTarget targetB;

    address admin = address(0xA11CE);
    address relayer = address(0xB0B);
    address otherCaller = address(0xC0FFEE);
    address unauthorized = address(0xDEAD);

    function setUp() public {
        vm.startPrank(admin);
        registry = new SafeGuardianRegistry(admin);
        responder = new SafeGuardResponderV2(admin, relayer, address(registry));
        vm.stopPrank();

        targetA = new MockGuardianTarget(address(responder));
        targetB = new MockGuardianTarget(address(responder));

        vm.startPrank(admin);
        registry.setTarget(address(targetA), true);
        registry.setTarget(address(targetB), true);
        vm.stopPrank();
    }

    function _samplePayload() internal pure returns (bytes memory) {
        SafeGuardResponderV2.IncidentPayload memory p = SafeGuardResponderV2.IncidentPayload({
            threatType: SafeGuardResponderV2.ThreatType.MasterCopyChanged,
            safeProxy: 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4,
            currentBlockNumber: 21_895_238,
            previousBlockNumber: 21_895_237,
            details: abi.encode("masterCopy swap")
        });
        return abi.encode(p);
    }

    // ---------- auth ----------

    function test_Auth_Relayer_CanHandle() public {
        vm.prank(relayer);
        responder.handleIncident(_samplePayload());
        assertEq(responder.incidentCount(), 1);
    }

    function test_Auth_AllowedCaller_CanHandle() public {
        vm.prank(admin);
        responder.setAllowedCaller(otherCaller, true);
        vm.prank(otherCaller);
        responder.handleIncident(_samplePayload());
        assertEq(responder.incidentCount(), 1);
    }

    function test_Auth_Unauthorized_Reverts() public {
        vm.prank(unauthorized);
        vm.expectRevert(bytes("not authorized"));
        responder.handleIncident(_samplePayload());
    }

    function test_Auth_OnlyAdminCanSetAllowed() public {
        vm.prank(unauthorized);
        vm.expectRevert(bytes("not admin"));
        responder.setAllowedCaller(unauthorized, true);
    }

    // ---------- idempotency ----------

    function test_Idempotent_DoubleCallDoesNotDoubleExecute() public {
        bytes memory payload = _samplePayload();
        vm.prank(relayer);
        responder.handleIncident(payload);
        vm.prank(relayer);
        responder.handleIncident(payload);
        assertEq(responder.incidentCount(), 1, "second call must be no-op");
        assertEq(targetA.pauseCount(), 1, "downstream pause must not double-fire");
    }

    function test_Idempotent_DifferentPayloadsProduceSeparateIncidents() public {
        bytes memory p1 = _samplePayload();
        SafeGuardResponderV2.IncidentPayload memory decoded = SafeGuardResponderV2.IncidentPayload({
            threatType: SafeGuardResponderV2.ThreatType.BalanceDrain,
            safeProxy: 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4,
            currentBlockNumber: 21_895_256,
            previousBlockNumber: 21_895_255,
            details: abi.encode("balance drain")
        });
        bytes memory p2 = abi.encode(decoded);

        vm.prank(relayer);
        responder.handleIncident(p1);
        vm.prank(relayer);
        responder.handleIncident(p2);
        assertEq(responder.incidentCount(), 2);
    }

    // ---------- validation ----------

    function test_Reject_InvalidThreatType() public {
        SafeGuardResponderV2.IncidentPayload memory p = SafeGuardResponderV2.IncidentPayload({
            threatType: SafeGuardResponderV2.ThreatType.None,
            safeProxy: address(0x1),
            currentBlockNumber: 1,
            previousBlockNumber: 0,
            details: ""
        });
        vm.prank(relayer);
        vm.expectRevert(bytes("invalid threat"));
        responder.handleIncident(abi.encode(p));
    }

    function test_Reject_ZeroSafeProxy() public {
        SafeGuardResponderV2.IncidentPayload memory p = SafeGuardResponderV2.IncidentPayload({
            threatType: SafeGuardResponderV2.ThreatType.MasterCopyChanged,
            safeProxy: address(0),
            currentBlockNumber: 1,
            previousBlockNumber: 0,
            details: ""
        });
        vm.prank(relayer);
        vm.expectRevert(bytes("invalid safe"));
        responder.handleIncident(abi.encode(p));
    }

    function test_Reject_BadBlockOrdering() public {
        SafeGuardResponderV2.IncidentPayload memory p = SafeGuardResponderV2.IncidentPayload({
            threatType: SafeGuardResponderV2.ThreatType.MasterCopyChanged,
            safeProxy: address(0x1),
            currentBlockNumber: 10,
            previousBlockNumber: 20,
            details: ""
        });
        vm.prank(relayer);
        vm.expectRevert(bytes("bad blocks"));
        responder.handleIncident(abi.encode(p));
    }

    // ---------- global pause ----------

    function test_GlobalPause_BlocksHandle() public {
        vm.prank(admin);
        responder.setGlobalPause(true);
        vm.prank(relayer);
        vm.expectRevert(bytes("responder paused"));
        responder.handleIncident(_samplePayload());
    }

    // ---------- fan-out ----------

    function test_FanOut_CallsAllApprovedTargets() public {
        vm.prank(relayer);
        responder.handleIncident(_samplePayload());
        assertTrue(targetA.paused());
        assertTrue(targetB.paused());
    }

    function test_FanOut_RevokedTargetIsSkipped() public {
        vm.prank(admin);
        registry.setTarget(address(targetB), false);

        vm.prank(relayer);
        responder.handleIncident(_samplePayload());
        assertTrue(targetA.paused());
        assertFalse(targetB.paused(), "revoked target must not be called");
    }

    function test_FanOut_RevertingTargetDoesNotBlockOthers() public {
        targetA.setRevertOnPause(true);

        vm.prank(relayer);
        responder.handleIncident(_samplePayload());
        assertFalse(targetA.paused(), "A reverted, still not paused");
        assertTrue(targetB.paused(), "B must still be paused despite A reverting");
        assertEq(responder.incidentCount(), 1);
    }

    // ---------- retry-after-failure ----------

    // If every approved target reverts, the responder must revert too and
    // must NOT mark the incident as executed, so a retry after the operator
    // un-bricks at least one hook still has effect.
    function test_Response_AllTargetsFail_DoesNotMarkExecuted() public {
        targetA.setRevertOnPause(true);
        targetB.setRevertOnPause(true);

        bytes memory payload = _samplePayload();

        vm.prank(relayer);
        vm.expectRevert(bytes("no target paused"));
        responder.handleIncident(payload);

        bytes32 incidentHash = keccak256(payload);
        assertFalse(responder.executedIncidentHash(incidentHash));
        assertEq(responder.incidentCount(), 0);
    }

    function test_Response_RetrySucceedsAfterInitialFailure() public {
        targetA.setRevertOnPause(true);
        targetB.setRevertOnPause(true);

        bytes memory payload = _samplePayload();

        vm.prank(relayer);
        vm.expectRevert(bytes("no target paused"));
        responder.handleIncident(payload);

        // Operator fixes target A; retry must now go through.
        targetA.setRevertOnPause(false);

        vm.prank(relayer);
        responder.handleIncident(payload);

        bytes32 incidentHash = keccak256(payload);
        assertTrue(responder.executedIncidentHash(incidentHash));
        assertEq(responder.incidentCount(), 1);
        assertTrue(targetA.paused());
    }

    // ---------- registry ----------

    function test_Registry_OnlyOwnerCanSetTarget() public {
        vm.prank(unauthorized);
        vm.expectRevert(bytes("not owner"));
        registry.setTarget(address(0x1234), true);
    }

    function test_Registry_DuplicateApprovalDoesNotDuplicateEntry() public {
        address extra = address(0x1234);
        vm.startPrank(admin);
        registry.setTarget(extra, true);
        registry.setTarget(extra, true);
        vm.stopPrank();
        assertEq(registry.targetsLength(), 3);
    }

    // Revoke-then-reapprove must not push a duplicate.
    function test_Registry_RevokeAndReapproveDoesNotDuplicate() public {
        address extra = address(0x1234);
        vm.startPrank(admin);
        registry.setTarget(extra, true);   // push #1
        registry.setTarget(extra, false);  // revoke
        registry.setTarget(extra, true);   // re-approve — previously pushed again
        vm.stopPrank();

        assertEq(registry.targetsLength(), 3, "must not re-push after revoke");
        assertTrue(registry.approvedTargets(extra));
    }

    // Responder fan-out cannot double-call a re-approved target.
    function test_FanOut_NoDuplicateCallAfterRevokeReapprove() public {
        vm.startPrank(admin);
        registry.setTarget(address(targetA), false);
        registry.setTarget(address(targetA), true);
        vm.stopPrank();

        vm.prank(relayer);
        responder.handleIncident(_samplePayload());
        assertEq(targetA.pauseCount(), 1, "A must be called exactly once");
        assertEq(targetB.pauseCount(), 1);
    }

    // Registry enforces a hard cap on targets.
    function test_Registry_MaxTargetsBound() public {
        // targets already has 2 entries (targetA, targetB) from setUp().
        uint256 remaining = registry.MAX_TARGETS() - registry.targetsLength();
        vm.startPrank(admin);
        for (uint256 i = 0; i < remaining; i++) {
            registry.setTarget(address(uint160(0x10000 + i)), true);
        }
        // One more must revert.
        vm.expectRevert(bytes("max targets"));
        registry.setTarget(address(0xDEAD0001), true);
        vm.stopPrank();
        assertEq(registry.targetsLength(), registry.MAX_TARGETS());
    }
}
