// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TrapDeployConfig
/// @notice Compile-time configuration consumed by BybitSafeTrapV2.
///         Drosera's deployment model produces traps with no constructor args,
///         so all per-deployment addresses live here as `internal constant`
///         and are wired into the trap via `pure` accessor functions. Edit
///         these values, recompile, and redeploy — there is no on-chain state
///         to rotate.
///
///         BASELINE_FEEDER must point at a deployed BaselineFeeder governed by
///         the operator's emergency multisig. The placeholder value below is
///         the all-ones address; replace it before building for production.
library TrapDeployConfig {
    /// @notice Bybit cold-wallet Safe proxy (the real, mainnet-deployed multisig
    ///         compromised on 2025-02-21 in the $1.46B incident).
    address internal constant SAFE_PROXY =
        0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4;

    /// @notice BaselineFeeder address. Replace before build with the operator's
    ///         deployed feeder. The tests overlay a BaselineFeeder at this same
    ///         address via Foundry's `deployCodeTo` cheatcode.
    address internal constant BASELINE_FEEDER =
        0x1111111111111111111111111111111111111111;

    /// @notice Lido stETH.
    address internal constant STETH =
        0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

    /// @notice Mantle mETH.
    address internal constant METH =
        0xd5F7838F5C461fefF7FE49ea5ebaF7728bB0ADfa;

    /// @notice Mantle cmETH.
    address internal constant CMETH =
        0xe3C063B1BEe9de02eb28352b55D49D85514C67FF;
}
