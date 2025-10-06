// SPDX-License-Identifier: GPL-3.0-or-later
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity >=0.7.6 <0.9.0;
pragma abicoder v2;

import {IERC20, GPv2Trade, GPv2Interaction, GPv2Authentication} from "cow/GPv2Settlement.sol";

interface CowSettlement {
    function settle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external;
}

/**
 * @dev Interface defining required methods for wrappers of the GPv2Settlement contract for CoW orders
 * A wrapper should:
 * * call the equivalent `settle` on the GPv2Settlement contract (0x9008D19f58AAbD9eD0D60971565AA8510560ab41)
 * * verify that the caller is authorized via the GPv2Authentication contract.
 * A wrapper may also execute, or otherwise put the blockchain in a state that needs to be established prior to settlement.
 * Additionally, it needs to be approved by the GPv2Authentication contract
 */
abstract contract CowWrapper is CowSettlement {
    event GasLeft(uint256);
    error NotASolver(address unauthorized);
    error WrapperHasNoSettleTarget(uint256 settleDataLength, uint256 fullCalldataLength);

    GPv2Authentication public immutable AUTHENTICATOR;

    constructor(GPv2Authentication authenticator_) {
        // retrieve the authentication we are supposed to use from the settlement contract
        AUTHENTICATOR = authenticator_;
    }

    /**
     * @dev Called to initiate a wrapped call against the settlement function. See GPv2Settlement.settle() for more information.
     */
    function settle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external {
        //emit GasLeft(gasleft());
        // Revert if not a valid solver
        if (!AUTHENTICATOR.isSolver(msg.sender)) {
            revert NotASolver(msg.sender);
        }
        //emit GasLeft(gasleft());

        // Extract additional data appended after settle calldata
        uint256 settleLength = _settleCalldataLength(tokens, clearingPrices, trades, interactions);
        //emit GasLeft(gasleft());

        // Require additional data for next settlement address
        if (msg.data.length < settleLength + 32) {
            revert WrapperHasNoSettleTarget(settleLength, msg.data.length);
        }

        // Additional data exists after the settle parameters
        bytes calldata additionalData = msg.data[settleLength:];

        _wrap(tokens, clearingPrices, trades, interactions, additionalData);
    }

    /**
     * @dev The logic for the wrapper. During this function, `_internalSettle` should be called
     */
    function _wrap(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrapperData
    ) internal virtual;

    function _internalSettle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrapperData
    ) internal {
        //emit GasLeft(gasleft());
        // the next settlement address to call will be the next word of the wrapper data
        address nextSettlement = abi.decode(wrapperData, (address));
        wrapperData = wrapperData[32:];
        // Encode the settle call
        bytes memory fullCalldata;
        if (wrapperData.length >= 32) {
            fullCalldata =
                abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);

            assembly {
                // add 0x20 because of the length of the fullCalldata itself at beginning we want to always skip
                let origLength := add(mload(fullCalldata), 0x20)
                let newLength := add(origLength, wrapperData.length)
                mstore(fullCalldata, sub(newLength, 0x20))
                mstore(0x40, add(fullCalldata, newLength))
                calldatacopy(add(fullCalldata, origLength), wrapperData.offset, wrapperData.length)
            }
        } else {
            fullCalldata =
                abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
            // no wrapperData to append
        }
        //emit GasLeft(gasleft());

        // Call UPSTREAM_SETTLEMENT with the full calldata
        (bool success, bytes memory returnData) = nextSettlement.call(fullCalldata);
        if (!success) {
            // Bubble up the revert reason
            assembly {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
    }

    /**
     * @dev Computes the length of the settle() calldata in bytes.
     * This can be used to determine if there is additional data appended to msg.data.
     * @return The length in bytes of the settle() function calldata
     */
    function _settleCalldataLength(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) internal pure returns (uint256) {
        // 4 bytes for function selector
        // + 4 * 32 bytes for the 4 dynamic array offset pointers
        // + length of each dynamic array data
        uint256 length = 4 + 4 * 32;

        // tokens array: 32 bytes for length + 32 bytes per token address
        length += 32 + tokens.length * 32;

        // clearingPrices array: 32 bytes for length + 32 bytes per price
        length += 32 + clearingPrices.length * 32;

        // trades array: 32 bytes for length + offset pointers + trade data
        length += 32;
        // Each trade needs an offset pointer in the array
        uint256 tradesLength = trades.length;
        length += tradesLength * 32;
        for (uint256 i = 0; i < tradesLength; i++) {
            // Each trade struct has fixed and dynamic parts
            // Fixed fields: sellTokenIndex, buyTokenIndex, receiver, sellAmount, buyAmount, validTo, appData, feeAmount, flags, executedAmount: 10 * 32 bytes
            // Dynamic field pointer for signature: 32 bytes
            // Signature length: 32 bytes
            // Signature data: trades[i].signature.length bytes (padded to 32-byte boundary)
            length += 11 * 32 + 32 + ((trades[i].signature.length + 31) / 32) * 32;
        }

        // interactions array (fixed array of 3 dynamic arrays)
        for (uint256 i = 0; i < 3; i++) {
            // 32 bytes for offset to this interaction array
            length += 32;
        }
        for (uint256 i = 0; i < 3; i++) {
            // 32 bytes for length of this interaction array
            length += 32;
            // 32 bytes for offset pointer to each interaction struct
            uint256 interactionsLength = interactions[i].length;
            length += interactions[i].length * 32;
            for (uint256 j = 0; j < interactionsLength; j++) {
                // Each interaction struct: target (32 bytes), value (32 bytes), callData offset (32 bytes)
                // callData length (32 bytes) + callData (padded to 32-byte boundary)
                length += 3 * 32 + 32 + ((interactions[i][j].callData.length + 31) / 32) * 32;
            }
        }

        return length;
    }
}
