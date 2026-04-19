// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SafeGuardResponder
 * @notice Drosera response contract for Safe{Wallet} multisig protection.
 *         When the BybitSafeTrap fires, Drosera operators submit a transaction
 *         calling handleIncident() with the threat type and details payload.
 *
 * @dev This is a tech demo responder. In production, this contract would:
 *   1. Pause dependent protocol contracts that rely on the compromised wallet
 *   2. Revoke approvals the wallet has granted to other contracts
 *   3. Alert governance and security teams
 *   4. Freeze pending transactions in a timelock queue
 *
 *   Auth model: allowlist-based. The admin configures which addresses can call
 *   handleIncident(). In Drosera, the actual msg.sender may be an operator EOA,
 *   relayer, or protocol executor — not a single fixed address.
 *
 *   The response function signature must match drosera.toml:
 *   handleIncident(uint8,bytes)
 */
contract SafeGuardResponder {
    // ======================== State ========================

    bool public isPaused;
    address public admin;

    mapping(address => bool) public allowedCallers;

    uint256 public lastIncidentBlock;
    uint8 public lastThreatType;
    bytes public lastDetails;
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

    event IncidentDetected(
        address indexed triggeredBy,
        uint256 blockNumber,
        uint8 threatType,
        bytes details
    );

    event EmergencyUnpaused(address indexed triggeredBy, uint256 blockNumber);
    event CallerAllowanceChanged(address indexed caller, bool allowed);

    // ======================== Modifiers ========================

    modifier onlyAdmin() {
        require(msg.sender == admin, "SafeGuardResponder: not admin");
        _;
    }

    modifier onlyAllowed() {
        require(allowedCallers[msg.sender], "SafeGuardResponder: not allowed");
        _;
    }

    // ======================== Constructor ========================

    /// @param _admin The admin address that can manage the allowlist and unpause.
    constructor(address _admin) {
        admin = _admin;
    }

    // ======================== Admin Functions ========================

    /// @notice Add or remove an address from the caller allowlist.
    function setAllowed(address caller, bool allowed) external onlyAdmin {
        allowedCallers[caller] = allowed;
        emit CallerAllowanceChanged(caller, allowed);
    }

    // ======================== Response Function ========================

    /// @notice Called by Drosera when the trap fires.
    ///         The function signature must match drosera.toml: handleIncident(uint8,bytes)
    /// @param _threatType The type of threat detected (1-8, see constants)
    /// @param _details ABI-encoded vector-specific details
    function handleIncident(uint8 _threatType, bytes calldata _details) external onlyAllowed {
        require(!isPaused, "SafeGuardResponder: already paused");

        isPaused = true;
        lastIncidentBlock = block.number;
        lastThreatType = _threatType;
        lastDetails = _details;
        incidentCount++;

        emit IncidentDetected(
            msg.sender,
            block.number,
            _threatType,
            _details
        );
    }

    /// @notice Unpause after the incident has been resolved.
    ///         Only admin (governance) can unpause.
    function emergencyUnpause() external onlyAdmin {
        require(isPaused, "SafeGuardResponder: not paused");
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
        uint8 threatType,
        bytes memory details,
        uint256 totalIncidents
    ) {
        return (isPaused, lastIncidentBlock, lastThreatType, lastDetails, incidentCount);
    }
}
