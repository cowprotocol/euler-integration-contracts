// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

/// @title Errors
/// @notice A collection of errors shared between contracts for `euler-integration-contracts`
library Errors {
    /// @dev Indicates that a user attempted to interact with an account that is not their own
    error SubaccountMustBeControlledByOwner(address subaccount, address owner);
}
