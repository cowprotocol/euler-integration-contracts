// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.30;

import {IEVC} from "./vendor/interfaces/IEthereumVaultConnector.sol";
import {IGPv2Settlement, GPv2Interaction, GPv2Trade} from "./vendor/interfaces/IGPv2Settlement.sol";
import {IGPv2Authentication} from "./vendor/interfaces/IGPv2Authentication.sol";

import "forge-std/console.sol";

/// @title CowEvcWrapper
/// @notice A wrapper around the EVC that allows for settlement operations
contract CowEvcWrapper {
    IEVC public immutable EVC;
    IGPv2Settlement public immutable SETTLEMENT;

    error Unauthorized(address msgSender);

    constructor(address _evc, address payable _settlement) {
        EVC = IEVC(_evc);
        SETTLEMENT = IGPv2Settlement(_settlement);
    }

    /// @notice Specifies the EVC calls that will need to be executed 
    /// around a GPv2Settlement 
    /// call prior to `settle` call on this contract
    /// @param preItems Items to execute before settlement
    /// @param postItems Items to execute after settlement
    function setEvcCalls(
        IEVC.BatchItem[] calldata preItems,
        IEVC.BatchItem[] calldata postItems
    ) external {
        _copyToTransientStorage(preItems, keccak256("preSettlementItems"));
        _copyToTransientStorage(postItems, keccak256("postSettlementItems"));
    }

    /// @notice Executes a batch of EVC operations with a settlement in between
    /// @param tokens Tokens involved in settlement
    /// @param clearingPrices Clearing prices for settlement
    /// @param trades Trade data for settlement
    /// @param interactions Interaction data for settlement
    function settle(
        address[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external payable {
        // Revert if not a valid solver
        if (!IGPv2Authentication(SETTLEMENT.authenticator()).isSolver(msg.sender)) {
            revert("CowEvcWrapper: not a solver");
        }

        // Create a single batch with all items
        IEVC.BatchItem[] memory preSettlementItems = _readFromTransientStorage(keccak256("preSettlementItems"));
        IEVC.BatchItem[] memory postSettlementItems = _readFromTransientStorage(keccak256("postSettlementItems"));
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](preSettlementItems.length + postSettlementItems.length + 1);

        // Copy pre-settlement items
        for (uint256 i = 0; i < preSettlementItems.length; i++) {
            items[i] = preSettlementItems[i];
            uint256 ptr; uint256 ptr2;
            IEVC.BatchItem memory subItem = preSettlementItems[i];
            bytes memory itemsData = preSettlementItems[i].data;
            assembly {
                ptr := itemsData
                ptr2 := subItem
            }
        }

        // Add settlement call to wrapper
        items[preSettlementItems.length] = IEVC.BatchItem({
            onBehalfOfAccount: msg.sender,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.internalSettle, (tokens, clearingPrices, trades, interactions))
        });

        // Copy post-settlement items
        for (uint256 i = 0; i < postSettlementItems.length; i++) {
            items[preSettlementItems.length + 1 + i] = postSettlementItems[i];
        }

        // Execute all items in a single batch
        EVC.batch(items);
    }

    /// @notice Executes a batch of EVC operations
    /// @param tokens Tokens involved in settlement
    /// @param clearingPrices Clearing prices for settlement
    /// @param trades Trade data for settlement
    /// @param interactions Interaction data for settlement
    function internalSettle(
        address[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external payable {
        if (msg.sender != address(EVC)) {
            revert Unauthorized(msg.sender);
        }

        SETTLEMENT.settle(tokens, clearingPrices, trades, interactions);
    }

    function _copyToTransientStorage(IEVC.BatchItem[] memory batch, bytes32 startSlot) internal {
        assembly {
            // Get the memory pointer and length of the input array.
            let batchPtr := batch
            let batchLen := mload(batchPtr)

            // A counter for the transient storage slot key.
            let slotCounter := startSlot

            // Store the overall array length at the start slot.
            tstore(slotCounter, batchLen)
            slotCounter := add(slotCounter, 1)

            // Iterate over each struct in the array.
            for { let i := 0 } lt(i, batchLen) { i := add(i, 1) } {
                // Each struct in a memory array occupies a fixed size plus the
                // dynamic data's pointer. In this case, 4 words: 3 for fixed fields,
                // and 1 for the pointer to the `bytes` data.
                let structPtr := mload(add(batchPtr, mul(0x20, add(1, i))))

                // Load and store the fixed-size fields.
                // Field 1: `targetContract`
                let target := mload(structPtr)
                tstore(slotCounter, target)
                slotCounter := add(slotCounter, 1)

                // Field 2: `onBehalfOf`
                let onBehalf := mload(add(structPtr, 0x20))
                tstore(slotCounter, onBehalf)
                slotCounter := add(slotCounter, 1)

                // Field 3: `value`
                let val := mload(add(structPtr, 0x40))
                tstore(slotCounter, val)
                slotCounter := add(slotCounter, 1)

                // Handle the dynamic-length `bytes` field.
                // This is the most complex part of the process.
                // The memory word for `data` is a pointer to the actual data.
                let dataPtr := mload(add(structPtr, 0x60))
                let dataLen := mload(dataPtr)

                // Store the length of the `bytes` data.
                tstore(slotCounter, dataLen)
                slotCounter := add(slotCounter, 1)

                // Calculate the number of 32-byte words for the `bytes` data.
                let dataWords := div(add(dataLen, 31), 32)
                let currentDataPtr := add(dataPtr, 0x20) // Skip the length word

                // Loop to copy each word of the bytes data.
                for { let j := 0 } lt(j, dataWords) { j := add(j, 1) } {
                    let word := mload(add(currentDataPtr, mul(j, 0x20)))
                    tstore(slotCounter, word)
                    slotCounter := add(slotCounter, 1)
                }
            }
        }
    }

    /**
     * @notice Reads an array of `BatchType` structs from transient storage.
     * @dev This function is for testing purposes to verify that the `copy` function
     * works correctly. It reads from the same slot layout used for writing.
     * @param startSlot The starting transient storage slot.
     * @return retVal The array of structs read from transient storage.
     */
    function _readFromTransientStorage(bytes32 startSlot) internal view returns (IEVC.BatchItem[] memory retVal) {
        assembly {
            // Get the overall array length from the start slot.
            let slotCounter := startSlot
            let batchLen := tload(slotCounter)
            slotCounter := add(slotCounter, 1)

            // Allocate memory for the return array.
            // A struct with 4 fields occupies 4 * 32 bytes = 128 bytes in memory.
            let batchPtr := mload(0x40)
            let endOfArray := add(batchPtr, add(0x20, mul(batchLen, 0x20)))
            mstore(0x40, endOfArray)
            mstore(batchPtr, batchLen)

            // Iterate through the transient storage slots to reconstruct each struct.
            for { let i := 0 } lt(i, batchLen) { i := add(i, 1) } {
                let structPtr := mload(0x40)
                let endOfData := add(structPtr, 0x80)
                mstore(0x40, endOfData)

                // Load and store the fixed-size fields.
                mstore(add(structPtr, 0x00), tload(slotCounter))
                slotCounter := add(slotCounter, 1)

                mstore(add(structPtr, 0x20), tload(slotCounter))
                slotCounter := add(slotCounter, 1)

                mstore(add(structPtr, 0x40), tload(slotCounter))
                slotCounter := add(slotCounter, 1)

                // Load the length of the dynamic `bytes` field.
                let dataLen := tload(slotCounter)
                // Calculate the number of words to copy.
                let dataWords := div(add(dataLen, 31), 32)
                slotCounter := add(slotCounter, 1)

                // Allocate memory for the `bytes` data.
                let dataPtr := mload(0x40)
                endOfData := add(dataPtr, add(0x20, mul(0x20, dataWords)))
                mstore(0x40, endOfData)
                mstore(dataPtr, dataLen)

                let currentDataPtr := add(dataPtr, 0x20)

                // Loop to load and copy each word of the bytes data.
                for { let j := 0 } lt(j, dataWords) { j := add(j, 1) } {
                    mstore(add(currentDataPtr, mul(j, 0x20)), tload(slotCounter))
                    slotCounter := add(slotCounter, 1)
                }

                // Store the pointer to the `bytes` data in the main struct.
                mstore(add(structPtr, 0x60), dataPtr)

                // Store the pointer to the structure in the array
                mstore(add(batchPtr, mul(0x20, add(1, i))), structPtr)
            }

            // Return the memory pointer to the reconstructed array.
            mstore(0x40, msize())
            retVal := batchPtr
            //return(batchPtr, sub(endOfArray, batchPtr))
        }
    }
}
