// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IEmergencyActionTarget} from "../SafeGuardianRegistry.sol";

/// @notice Downstream emergency-action target used in tests. Records each
///         pause call and lets the admin simulate failure via `setRevertOnPause`.
contract MockGuardianTarget is IEmergencyActionTarget {
    bool public override paused;
    address public responder;
    bytes public lastPayload;
    uint256 public pauseCount;
    bool public revertOnPause;

    event EmergencyPaused(address indexed caller, bytes payload);
    event EmergencyUnpaused(address indexed caller);

    modifier onlyResponder() {
        require(msg.sender == responder, "not responder");
        _;
    }

    constructor(address responder_) {
        require(responder_ != address(0), "zero responder");
        responder = responder_;
    }

    function emergencyPause(bytes calldata incidentPayload) external override onlyResponder {
        if (revertOnPause) revert("mock: forced revert");
        if (paused) return;
        paused = true;
        lastPayload = incidentPayload;
        pauseCount++;
        emit EmergencyPaused(msg.sender, incidentPayload);
    }

    function emergencyUnpause() external onlyResponder {
        paused = false;
        emit EmergencyUnpaused(msg.sender);
    }

    function setRevertOnPause(bool v) external {
        revertOnPause = v;
    }
}
