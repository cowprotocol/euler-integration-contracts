// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

/// @title MockEVC
/// @notice Mock implementation of EVC for unit testing
contract MockEVC {
    mapping(address => mapping(address => bool)) public operators;
    mapping(address => uint256) public nonces;
    address public onBehalfOf;
    uint256 public operatorMask = 0;

    error InvalidSignature();

    bytes32 private constant PERMIT_TYPEHASH = keccak256(
        "Permit(address signer,address sender,uint256 nonceNamespace,uint256 nonce,uint256 deadline,uint256 value,bytes data)"
    );

    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

    bytes32 private immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(DOMAIN_TYPE_HASH, keccak256("Ethereum Vault Connector"), block.chainid, address(this))
        );
    }

    function setOperatorMask(uint256 mask) external {
        operatorMask = mask;
    }

    function setOnBehalfOf(address shouldBeOnBehalfOf) external {
        onBehalfOf = shouldBeOnBehalfOf;
    }

    function setAccountOperator(address account, address operator, bool authorized) external {
        operators[account][operator] = authorized;
    }

    function getOperator(bytes19, address) external view returns (uint256) {
        return operatorMask;
    }

    function isAccountOperatorAuthorized(address account, address operator) external view returns (bool) {
        return operators[account][operator];
    }

    function getNonce(bytes19, uint256) external pure returns (uint256) {
        return 0;
    }

    function enableCollateral(address, address) external pure {}

    function enableController(address, address) external pure {}

    function disableCollateral(address, address) external pure {}

    function batch(IEVC.BatchItem[] calldata items) external returns (IEVC.BatchItemResult[] memory) {
        // Execute each item
        for (uint256 i = 0; i < items.length; i++) {
            // Set onBehalfOf to the item's onBehalfOfAccount for the duration of the call
            onBehalfOf = items[i].onBehalfOfAccount;

            (bool success, bytes memory reason) = items[i].targetContract.call(items[i].data);

            // reset onBehalfOf
            onBehalfOf = address(0);

            if (!success) {
                assembly ("memory-safe") {
                    revert(add(reason, 0x20), mload(reason))
                }
            }
        }

        return new IEVC.BatchItemResult[](0);
    }

    function permit(address, address, uint256, uint256, uint256, uint256, bytes memory, bytes memory) external view {}

    fallback() external {
        revert("Mock EVC does not implement the called function");
    }
}
