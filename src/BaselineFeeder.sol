// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BaselineFeeder
 * @notice Governance-owned per-Safe baseline configuration for BybitSafeTrapV2.
 *
 *         Traps cannot rely on constructor args for their `pure` comparison
 *         logic, so the expected `masterCopy`, `threshold`, `ownerCount`, and
 *         `ownersHash` values for each monitored Safe are stored here. The trap
 *         reads them at `collect()` time and embeds them in every snapshot,
 *         which lets `shouldRespond()` compare against them without reading
 *         state. Baseline rotation therefore happens on-chain, via this
 *         contract, without redeploying trap code.
 *
 *         Intended deployment: one BaselineFeeder instance per operator,
 *         owned by a governance multisig + timelock.
 */
contract BaselineFeeder {
    struct Baseline {
        address masterCopy;
        uint256 threshold;
        uint256 ownerCount;
        bytes32 ownersHash;
        bool configured;
    }

    address public owner;

    mapping(address => Baseline) internal _baselines;

    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    event BaselineSet(
        address indexed safe,
        address masterCopy,
        uint256 threshold,
        uint256 ownerCount,
        bytes32 ownersHash
    );
    event BaselineCleared(address indexed safe);

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

    /// @notice Set the governance-approved baseline for a Safe. `ownersHash`
    ///         may be left `bytes32(0)` to disable the absolute owners-hash
    ///         check (relative checks still fire).
    function setBaseline(
        address safe,
        address masterCopy_,
        uint256 threshold_,
        uint256 ownerCount_,
        bytes32 ownersHash_
    ) external onlyOwner {
        require(safe != address(0), "zero safe");
        require(masterCopy_ != address(0), "zero masterCopy");
        require(threshold_ > 0, "zero threshold");
        require(ownerCount_ > 0, "zero ownerCount");
        require(threshold_ <= ownerCount_, "threshold > owners");

        _baselines[safe] = Baseline({
            masterCopy: masterCopy_,
            threshold: threshold_,
            ownerCount: ownerCount_,
            ownersHash: ownersHash_,
            configured: true
        });

        emit BaselineSet(safe, masterCopy_, threshold_, ownerCount_, ownersHash_);
    }

    /// @notice Clear a Safe's baseline. After this, the trap will report
    ///         `baselineConfigured = false` and `shouldRespond` will skip
    ///         absolute checks but continue with relative checks.
    function clearBaseline(address safe) external onlyOwner {
        delete _baselines[safe];
        emit BaselineCleared(safe);
    }

    function getBaseline(address safe) external view returns (Baseline memory) {
        return _baselines[safe];
    }
}
