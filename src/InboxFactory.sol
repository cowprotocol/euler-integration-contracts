// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Create2} from "openzeppelin-contracts/contracts/utils/Create2.sol";
import {Inbox, InboxLibrary} from "./Inbox.sol";

/// @title InboxFactory
/// @notice Mixin contract for managing Inbox contract creation and address computation
/// @dev Provides utilities for computing and deploying Inbox contracts used in wrapper operations
contract InboxFactory {
    /// @notice Settlement contract address used for Inbox creation
    /// @dev Stored as immutable to avoid name collision with CowWrapper's public SETTLEMENT
    address internal immutable INBOX_SETTLEMENT;

    /// @notice Indicates that the computed Create2 address does not match the expected address
    error Create2AddressMismatch(address expectedAddress);

    /// @notice Initialize the factory with a settlement address
    /// @param settlement The settlement contract address to use for Inbox creation
    constructor(address settlement) {
        INBOX_SETTLEMENT = settlement;
    }

    /// @notice Get or create an Inbox contract for the given owner and subaccount
    /// @dev Deploys the Inbox if it doesn't exist yet
    /// @param owner The owner address
    /// @param subaccount The subaccount address
    /// @return The address of the Inbox contract
    function getInbox(address owner, address subaccount) external returns (address) {
        return address(_getInbox(owner, subaccount));
    }

    /// @notice Get the creation code used for the deployed Inboxes. Does not include any constructor params that may need to be appended. Useful for computing the deployed Inbox address wihout needing to make an on-chain call
    /// @return creationCode The creation code that will be used.
    function getInboxCreationCode() external pure returns (bytes memory creationCode) {
        return type(Inbox).creationCode;
    }

    /// @notice Get the address where an Inbox would be deployed without deploying it, and the domain separator needed to sign a message to it
    /// @dev This is a view-only function that only returns the address and domain separator
    /// @param owner The owner address
    /// @param subaccount The subaccount address
    /// @return creationAddress The computed Inbox address
    /// @return domainSeparator The domain separator for the Inbox contract
    function getInboxAddressAndDomainSeparator(address owner, address subaccount)
        external
        view
        returns (address creationAddress, bytes32 domainSeparator)
    {
        (creationAddress,,) = _getInboxAddress(owner, subaccount);
        domainSeparator = InboxLibrary.computeDomainSeparator(creationAddress);
    }

    /// @notice Compute the Inbox address for a given owner and subaccount (view-only, does not deploy)
    /// @param owner The owner address
    /// @param subaccount The subaccount address
    /// @return creationAddress The computed Inbox address
    /// @return creationCode The code needed to create the contract
    /// @return salt The salt that should be used to create the contract
    function _getInboxAddress(address owner, address subaccount)
        internal
        view
        returns (address creationAddress, bytes memory creationCode, bytes32 salt)
    {
        salt = bytes32(uint256(uint160(subaccount)));
        creationCode = abi.encodePacked(type(Inbox).creationCode, abi.encode(address(this), owner, INBOX_SETTLEMENT));
        creationAddress = Create2.computeAddress(salt, keccak256(creationCode));
    }

    /// @notice Get or create an Inbox contract instance
    /// @dev Deploys the Inbox if it doesn't exist yet
    /// @param owner The owner address
    /// @param subaccount The subaccount address
    /// @return The Inbox contract instance
    function _getInbox(address owner, address subaccount) internal returns (Inbox) {
        (address expectedAddress, bytes memory creationCode, bytes32 salt) = _getInboxAddress(owner, subaccount);

        if (expectedAddress.code.length == 0) {
            // `require` here is mostly for sanity
            // NOTE: its technically possible to deploy create2 directly using new Contract{salt: }(), but openzeppelin usage
            // is good for consistency
            require(Create2.deploy(0, salt, creationCode) == expectedAddress, Create2AddressMismatch(expectedAddress));
        }

        return Inbox(expectedAddress);
    }
}
