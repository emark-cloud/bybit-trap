// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IEmergencyActionTarget {
    function emergencyPause(bytes calldata incidentPayload) external;
    function paused() external view returns (bool);
}

/**
 * @title SafeGuardianRegistry
 * @notice Bounded allowlist of approved emergency-action targets for
 *         SafeGuardResponderV2.
 *
 *         Production responders should not hardcode a single downstream pause hook.
 *         This registry lets a governance owner add, rotate, or remove approved
 *         emergency targets without redeploying the responder. The responder
 *         fans out each incident to every approved target.
 *
 *         - Each target is inserted into `targets` at most once (tracked via
 *           the `_seen` map), so revoke-then-re-approve does NOT push a
 *           duplicate. `approvedTargets` is the boolean flag gating fan-out.
 *         - Total targets are capped at `MAX_TARGETS` so the responder's
 *           on-chain fan-out loop has a bounded gas surface and cannot be
 *           DoS'd by an over-large registry.
 */
contract SafeGuardianRegistry {
    /// @notice Hard cap on the number of emergency targets ever inserted.
    ///         Bounds responder fan-out gas.
    uint256 public constant MAX_TARGETS = 16;

    address public owner;

    mapping(address => bool) public approvedTargets;

    /// @dev Internal flag: has this target ever been inserted into `targets`?
    ///      Prevents duplicate pushes across approve→revoke→re-approve cycles.
    mapping(address => bool) internal _seen;

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
    /// @dev A target is appended to `targets` at most once (the first time it
    ///      is seen) and stays in the array for the life of the registry,
    ///      keeping indices stable for off-chain observers. `approvedTargets`
    ///      is the live flag the responder reads during fan-out.
    function setTarget(address target, bool approved) external onlyOwner {
        require(target != address(0), "zero target");

        if (!_seen[target]) {
            require(targets.length < MAX_TARGETS, "max targets");
            _seen[target] = true;
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
