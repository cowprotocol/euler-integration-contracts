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

import "forge-std/console.sol";

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
        (, uint256 settleLength) = _settleCalldataLength(tokens, interactions);
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
        address nextSettlement;
        //= abi.decode(wrapperData, (address));
        assembly {
            nextSettlement := calldataload(wrapperData.offset)
        }
        wrapperData = wrapperData[32:];
        // Encode the settle call
        bytes memory fullCalldata;
        (uint256 settleStart, uint256 settleEnd) = _settleCalldataLength(tokens, interactions);
        //console.logBytes(msg.data[settleStart:settleEnd]);

        (bool success, bytes memory returnData) = nextSettlement.call(abi.encodePacked(CowSettlement.settle.selector, msg.data[settleStart:settleEnd], wrapperData));

        //(bool success, bytes memory returnData) = nextSettlement.call(fullCalldata);
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
     * @return start The calldata position in bytes of the start of settle() function calldata
     * @return end The calldata position in bytes of the end of settle() function calldata
     */
    function _settleCalldataLength(
        IERC20[] calldata tokens,
        GPv2Interaction.Data[][3] calldata interactions
    ) internal pure returns (uint256 start, uint256 end) {
        GPv2Interaction.Data[] calldata lastInteractions = interactions[2];
        assembly {
            start := sub(tokens.offset, 160)
            end := add(lastInteractions.offset, lastInteractions.length)
        }
    }
}
