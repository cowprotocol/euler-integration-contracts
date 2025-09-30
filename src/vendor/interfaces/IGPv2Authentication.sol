// SPDX-License-Identifier: LGPL-3.0-or-later
pragma solidity ^0.8;

// Vendored from CoW Protocol settlement contract repo with minor modifications:
// - Modified Solidity version
// - Formatted code
// <https://github.com/cowprotocol/contracts/blob/main/src/contracts/interfaces/GPv2Authentication.sol>

/// @title Gnosis Protocol v2 Authentication Interface
/// @author Gnosis Developers
interface IGPv2Authentication {
    /// @dev determines whether the provided address is an authenticated solver.
    /// @param prospectiveSolver the address of prospective solver.
    /// @return true when prospectiveSolver is an authenticated solver, otherwise false.
    function isSolver(address prospectiveSolver) external view returns (bool);
}
