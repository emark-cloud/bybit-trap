// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SafeGuardResponder
 * @notice Drosera response contract for Safe{Wallet} multisig protection.
 *         When the BybitSafeTrap detects any compromise vector, Drosera
 *         operators call this contract to trigger an emergency response.
 *
 * @dev In a production deployment, this contract would:
 *   1. Pause all dependent protocol contracts that rely on the compromised wallet
 *   2. Revoke approvals the wallet has granted to other contracts
 *   3. Alert governance and security teams
 *   4. Freeze any pending transactions in a timelock queue
 *
 *   For this POC, we demonstrate the pause mechanism that Drosera would trigger.
 *   The response function signature must match what's configured in drosera.toml.
 */
contract SafeGuardResponder {
    // ======================== State ========================

    bool public isPaused;
    address public droseraOperator;

    uint256 public lastIncidentBlock;
    address public lastReportedImplementation;
    uint8 public lastThreatType;
    uint256 public incidentCount;

    // ======================== Threat Types ========================

    uint8 constant THREAT_IMPLEMENTATION_COMPROMISED = 1;
    uint8 constant THREAT_MASTERCOPY_CHANGED = 2;
    uint8 constant THREAT_MODULES_CHANGED = 3;
    uint8 constant THREAT_GUARD_CHANGED = 4;
    uint8 constant THREAT_CONFIG_CHANGED = 5;
    uint8 constant THREAT_BALANCE_DRAIN = 6;
    uint8 constant THREAT_GRADUAL_DRAIN = 7;
    uint8 constant THREAT_NONCE_JUMP = 8;

    // ======================== Events ========================

    event EmergencyPauseTriggered(
        address indexed triggeredBy,
        uint256 blockNumber,
        address reportedImplementation,
        address expectedImplementation,
        uint8 threatType
    );

    event EmergencyUnpaused(address indexed triggeredBy, uint256 blockNumber);

    // ======================== Modifiers ========================

    modifier onlyDrosera() {
        require(msg.sender == droseraOperator, "SafeGuardResponder: unauthorized");
        _;
    }

    modifier onlyWhenPaused() {
        require(isPaused, "SafeGuardResponder: not paused");
        _;
    }

    // ======================== Constructor ========================

    constructor(address _droseraOperator) {
        droseraOperator = _droseraOperator;
    }

    // ======================== Response Function ========================

    /// @notice Called by Drosera when the trap fires.
    ///         The function signature must match drosera.toml:
    ///         emergencyPause(address,address,uint8)
    /// @param _reportedImpl The implementation address detected by the trap
    /// @param _expectedImpl The expected (legitimate) implementation address
    /// @param _threatType The type of threat detected (see constants above)
    function emergencyPause(
        address _reportedImpl,
        address _expectedImpl,
        uint8 _threatType
    ) external onlyDrosera {
        require(!isPaused, "SafeGuardResponder: already paused");

        isPaused = true;
        lastIncidentBlock = block.number;
        lastReportedImplementation = _reportedImpl;
        lastThreatType = _threatType;
        incidentCount++;

        emit EmergencyPauseTriggered(
            msg.sender,
            block.number,
            _reportedImpl,
            _expectedImpl,
            _threatType
        );
    }

    /// @notice Unpause after the incident has been resolved.
    ///         In production, this would require multisig or governance approval.
    function emergencyUnpause() external onlyDrosera onlyWhenPaused {
        isPaused = false;
        emit EmergencyUnpaused(msg.sender, block.number);
    }

    // ======================== View Functions ========================

    /// @notice Check if operations should be blocked
    function isOperational() external view returns (bool) {
        return !isPaused;
    }

    /// @notice Get incident details
    function getIncidentInfo() external view returns (
        bool paused,
        uint256 incidentBlock,
        address reportedImpl,
        uint8 threatType,
        uint256 totalIncidents
    ) {
        return (isPaused, lastIncidentBlock, lastReportedImplementation, lastThreatType, incidentCount);
    }
}
