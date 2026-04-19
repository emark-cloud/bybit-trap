// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IEmergencyActionTarget {
    function emergencyPause(bytes calldata incidentPayload) external;
    function paused() external view returns (bool);
}

/**
 * @title SafeGuardianRegistry
 * @notice Allowlist of approved emergency-action targets for SafeGuardResponderV2.
 *
 *         Production responders should not hardcode a single downstream pause hook.
 *         This registry lets a governance owner add, rotate, or remove approved
 *         emergency targets without redeploying the responder. The responder
 *         fans out each incident to every approved target.
 *
 *         See GUIDELINES.md §9 "Guardian Registry (Fan-Out Pattern)".
 */
contract SafeGuardianRegistry {
    address public owner;

    mapping(address => bool) public approvedTargets;
    address[] public targets;

    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    event TargetApprovalUpdated(address indexed target, bool approved);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address initialOwner) {
        require(initialOwner != address(0), "zero owner");
        owner = initialOwner;
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Approve or revoke an emergency action target.
    /// @dev Targets are appended on first approval and remain in the `targets` array
    ///      after revocation (approvedTargets flag gates fan-out). This keeps the
    ///      index stable for off-chain observers.
    function setTarget(address target, bool approved) external onlyOwner {
        require(target != address(0), "zero target");

        if (approved && !approvedTargets[target]) {
            targets.push(target);
        }

        approvedTargets[target] = approved;
        emit TargetApprovalUpdated(target, approved);
    }

    function getTargets() external view returns (address[] memory) {
        return targets;
    }

    function targetsLength() external view returns (uint256) {
        return targets.length;
    }
}
