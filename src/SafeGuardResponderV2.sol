// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SafeGuardianRegistry, IEmergencyActionTarget} from "./SafeGuardianRegistry.sol";

/**
 * @title SafeGuardResponderV2
 * @notice Production-grade responder consumed by BybitSafeTrapV2.
 *
 *  - Accepts a single abi-encoded IncidentPayload via handleIncident(bytes).
 *  - Idempotent: replaying the same payload is a no-op.
 *  - Allowlisted callers (relayer + additional allowed addresses).
 *  - Global pause kill-switch for false-positive storms.
 *  - Fans out to every approved emergency target in SafeGuardianRegistry.
 *
 *  See GUIDELINES.md §9 (Response Contract Design).
 */
contract SafeGuardResponderV2 {
    struct IncidentPayload {
        uint8 threatType;
        address safeProxy;
        uint256 currentBlockNumber;
        uint256 previousBlockNumber;
        bytes details;
    }

    address public admin;
    address public relayer;
    SafeGuardianRegistry public immutable registry;

    bool public globallyPaused;
    uint256 public incidentCount;

    mapping(address => bool) public allowedCallers;
    mapping(bytes32 => bool) public executedIncidentHash;

    uint8 public lastThreatType;
    address public lastSafeProxy;
    uint256 public lastIncidentBlock;
    bytes public lastDetails;

    event AllowedCallerUpdated(address indexed caller, bool allowed);
    event RelayerUpdated(address indexed oldRelayer, address indexed newRelayer);
    event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
    event GlobalPauseStateSet(bool paused);

    event IncidentHandled(
        bytes32 indexed incidentHash,
        address indexed caller,
        address indexed safeProxy,
        uint8 threatType,
        uint256 currentBlockNumber,
        uint256 previousBlockNumber,
        bytes details
    );

    event DownstreamPauseAttempt(address indexed target, bool success);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    modifier onlyAuthorizedCaller() {
        require(msg.sender == relayer || allowedCallers[msg.sender], "not authorized");
        _;
    }

    constructor(address initialAdmin, address initialRelayer, address registry_) {
        require(initialAdmin != address(0), "zero admin");
        require(initialRelayer != address(0), "zero relayer");
        require(registry_ != address(0), "zero registry");

        admin = initialAdmin;
        relayer = initialRelayer;
        registry = SafeGuardianRegistry(registry_);
    }

    // ======================== Admin ========================

    function setAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero admin");
        emit AdminUpdated(admin, newAdmin);
        admin = newAdmin;
    }

    function setAllowedCaller(address caller, bool allowed) external onlyAdmin {
        require(caller != address(0), "zero caller");
        allowedCallers[caller] = allowed;
        emit AllowedCallerUpdated(caller, allowed);
    }

    function setRelayer(address newRelayer) external onlyAdmin {
        require(newRelayer != address(0), "zero relayer");
        emit RelayerUpdated(relayer, newRelayer);
        relayer = newRelayer;
    }

    function setGlobalPause(bool paused_) external onlyAdmin {
        globallyPaused = paused_;
        emit GlobalPauseStateSet(paused_);
    }

    // ======================== Incident entrypoint ========================

    /// @notice Drosera-configured response function. Signature must match
    ///         drosera.toml `response_function = "handleIncident(bytes)"`.
    function handleIncident(bytes calldata rawPayload) external onlyAuthorizedCaller {
        require(!globallyPaused, "responder paused");

        IncidentPayload memory payload = abi.decode(rawPayload, (IncidentPayload));
        require(payload.threatType > 0, "invalid threat");
        require(payload.safeProxy != address(0), "invalid safe");
        require(payload.currentBlockNumber >= payload.previousBlockNumber, "bad blocks");

        bytes32 incidentHash = keccak256(rawPayload);

        // Idempotent — replays are no-ops.
        if (executedIncidentHash[incidentHash]) {
            return;
        }
        executedIncidentHash[incidentHash] = true;

        incidentCount++;
        lastThreatType = payload.threatType;
        lastSafeProxy = payload.safeProxy;
        lastIncidentBlock = block.number;
        lastDetails = payload.details;

        emit IncidentHandled(
            incidentHash,
            msg.sender,
            payload.safeProxy,
            payload.threatType,
            payload.currentBlockNumber,
            payload.previousBlockNumber,
            payload.details
        );

        // Fan out to every approved emergency target.
        address[] memory targets = registry.getTargets();
        for (uint256 i = 0; i < targets.length; i++) {
            address target = targets[i];
            if (!registry.approvedTargets(target)) continue;

            bool success;
            try IEmergencyActionTarget(target).emergencyPause(rawPayload) {
                success = true;
            } catch {
                success = false;
            }

            emit DownstreamPauseAttempt(target, success);
        }
    }
}
