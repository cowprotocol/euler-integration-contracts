// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

/// @notice A contract for receiving funds from the CoW Settlement contract which can then be operated upon by a different contract in post (i.e. a wrapper)
/// @dev The contract has two associated accounts-- the OWNER, and the BENEFICIARY. Both associated accounts have the ability to execute arbitrary calls against this contract.
/// The purpose of the OWNER is to allow the wrapper or execute whatever operations it needs following a settlement contract operation without needing to store in the wrapper itself (ex. potentially intermingled with other user's funds) or the user's own wallet.
/// The purpose of the BENEFICIARY is to allow the ultimate holder of the funds to be able to access this contract in the case of trouble (ex. funds got stuck, etc.)
contract Inbox {
    address internal immutable OWNER;
    address internal immutable BENEFICIARY;

    error Unauthorized(address);

    constructor(address owner, address beneficiary) {
        OWNER = owner;
        BENEFICIARY = beneficiary;
    }

    /// @notice Allows the owner or beneficiary to execute an arbitrary call against this account
    /// @dev The call structure for this function is [bytes20 -- target address][bytes data], as encoded with `abi.encodePacked`.
    /// Also, if `value` is supplied, it will be forwarded onto the function being called.
    fallback() external payable {
        require(msg.sender == OWNER || msg.sender == BENEFICIARY, Unauthorized(msg.sender));

        assembly {
            // Get target address from calldata (first 20 bytes)
            let target := shr(96, calldataload(0))

            // Get data offset and length
            // bytes calldata offset is at position 20, contains offset to actual data
            let dataLength := sub(calldatasize(), 20)
            calldatacopy(0, 20, sub(calldatasize(), 20))

            // Execute call
            let success := call(gas(), target, callvalue(), 0, dataLength, 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) {
                revert(0, returndatasize())
            }
            // Return result
            return(0, returndatasize())
        }
    }
}
