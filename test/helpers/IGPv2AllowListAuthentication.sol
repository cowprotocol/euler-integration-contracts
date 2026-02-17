// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

import {ICowAuthentication} from "../../src/CowWrapper.sol";

/// @title Gnosis Protocol v2 Allow List Authentication Interface
/// @notice Minimal interface for the deployed GPv2AllowListAuthentication contract
/// @dev Only includes functions needed for testing
interface IGPv2AllowListAuthentication is ICowAuthentication {
    /// @dev Returns the address of the manager that has permissions to add and remove solvers
    function manager() external view returns (address);

    /// @dev Add an address to the set of allowed solvers
    /// @param solver The solver address to add
    function addSolver(address solver) external;
}
