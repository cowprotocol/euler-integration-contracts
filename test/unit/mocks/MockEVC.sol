// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

/// @title MockEVC
/// @notice Mock implementation of EVC for unit testing
contract MockEVC {
    mapping(address => mapping(address => bool)) public operators;
    mapping(address => uint256) public nonces;
    bool public shouldSucceed = true;

    function setOperator(address account, address operator, bool authorized) external {
        operators[account][operator] = authorized;
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
            (bool success, bytes memory reason) = items[i].targetContract.call(items[i].data);
            if (!success) {
                assembly {
                    revert(add(reason, 0x20), mload(reason))
                }
            }
        }

        return new IEVC.BatchItemResult[](0);
    }

    function setSuccessfulBatch(bool success) external {
        shouldSucceed = success;
    }

    function permit(address, address, uint256, uint256, uint256, uint256, bytes memory, bytes memory) external pure {}
}
