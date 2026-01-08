// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

/// @title MockEVC
/// @notice Mock implementation of EVC for unit testing
contract MockEVC {
    mapping(address => mapping(address => bool)) public operators;
    mapping(address => uint256) public nonces;
    bool public shouldSucceed = true;
    address public onBehalfOf;
    bool public shouldVerifySignatures = false;

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

    function setSignatureVerification(bool enabled) external {
        shouldVerifySignatures = enabled;
    }

    function setOperator(address account, address operator, bool authorized) external {
        operators[account][operator] = authorized;
    }

    function setOnBehalfOf(address shouldBeOnBehalfOf) external {
        onBehalfOf = shouldBeOnBehalfOf;
    }

    function setAccountOperator(address account, address operator, bool authorized) external {
        operators[account][operator] = authorized;
    }

    function getNonce(bytes19, uint256) external pure returns (uint256) {
        return 0;
    }

    function enableCollateral(address, address) external pure {}

    function enableController(address, address) external pure {}

    function disableCollateral(address, address) external pure {}

    function batch(IEVC.BatchItem[] calldata items) external returns (IEVC.BatchItemResult[] memory) {
        require(shouldSucceed, "MockEVC: batch failed");

        // Execute each item
        for (uint256 i = 0; i < items.length; i++) {
            // Set onBehalfOf to the item's onBehalfOfAccount for the duration of the call
            address previousOnBehalfOf = onBehalfOf;
            onBehalfOf = items[i].onBehalfOfAccount;

            (bool success, bytes memory reason) = items[i].targetContract.call(items[i].data);

            // Restore previous onBehalfOf
            onBehalfOf = previousOnBehalfOf;

            if (!success) {
                assembly ("memory-safe") {
                    revert(add(reason, 0x20), mload(reason))
                }
            }
        }

        return new IEVC.BatchItemResult[](0);
    }

    function setSuccessfulBatch(bool success) external {
        shouldSucceed = success;
    }

    function permit(
        address signer,
        address sender,
        uint256 nonceNamespace,
        uint256 nonce,
        uint256 deadline,
        uint256 value,
        bytes memory data,
        bytes memory signature
    ) external view {
        if (shouldVerifySignatures) {
            bytes32 structHash = keccak256(
                abi.encode(PERMIT_TYPEHASH, signer, sender, nonceNamespace, nonce, deadline, value, keccak256(data))
            );
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

            address recoveredSigner = ECDSA.recover(digest, signature);
            require(recoveredSigner == signer, InvalidSignature());
        }
    }

    function getCurrentOnBehalfOfAccount(address) external view returns (address, bool) {
        return (onBehalfOf, false);
    }
}
