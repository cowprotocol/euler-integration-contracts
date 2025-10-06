// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

library EVCTransientUtils {
    function copyToTransientStorage(IEVC.BatchItem[] memory batch, bytes32 startSlot) internal {
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
     * @param startSlot The starting transient storage slot.
     * @return retVal The array of structs read from transient storage.
     */
    function readFromTransientStorage(bytes32 startSlot) internal view returns (IEVC.BatchItem[] memory retVal) {
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
