// SPDX-License-Identifier: GPL-3.0-or-later
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
        // Revert if not a valid solver
        if (!AUTHENTICATOR.isSolver(msg.sender)) {
            revert NotASolver(msg.sender);
        }

        // Extract additional data appended after settle calldata
        uint256 settleEnd = _settleCalldataLength(interactions);

        // Require additional data for next settlement address
        if (msg.data.length < settleEnd + 32) {
            revert WrapperHasNoSettleTarget(settleEnd, msg.data.length);
        }

        // Additional data exists after the settle parameters
        bytes calldata additionalData = msg.data[settleEnd:];

        // the settle data will always be after the first 4 bytes (selector), up to the computed data end point
        _wrap(msg.data[4:settleEnd], additionalData);
    }

    /**
     * @dev The logic for the wrapper. During this function, `_internalSettle` should be called. `wrapperData` may be consumed as required for the wrapper's particular requirements
     */
    function _wrap(
        bytes calldata settleData,
        bytes calldata wrapperData
    ) internal virtual;

    function _internalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData
    ) internal {
        // the next settlement address to call will be the next word of the wrapper data
        address nextSettlement;
        assembly {
            nextSettlement := calldataload(wrapperData.offset)
        }
        wrapperData = wrapperData[32:];
        // Encode the settle call
        bytes memory fullCalldata;

        (bool success, bytes memory returnData) = nextSettlement.call(abi.encodePacked(CowSettlement.settle.selector, settleData, wrapperData));

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
     * @return end The calldata position in bytes of the end of settle() function calldata
     */
    function _settleCalldataLength(
        GPv2Interaction.Data[][3] calldata interactions
    ) internal pure returns (uint256 end) {
        // NOTE: technically this function could fail to return the correct length, if the data encoded in the ABI is provided indexed in an unusual order
        // however, doing a deeper check of the total data is very expensive and we are generally working with callers who provide data in a verifiably standardized format
        GPv2Interaction.Data[] calldata lastInteractions = interactions[2];
        assembly {
            end := add(lastInteractions.offset, lastInteractions.length)
        }
    }
}
