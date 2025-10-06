// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {IERC20, GPv2Trade, GPv2Interaction, GPv2Authentication} from "cow/GPv2Settlement.sol";

import {CowSettlement} from "src/vendor/CowWrapper.sol";

library CowWrapperHelpers {
    /**
     * @dev This function is intended for testing purposes and is not memory efficient.
     */
    function encodeWrapperCall(
        address[] calldata wrappers,
        bytes[] calldata wrapperDatas,
        address cowSettlement,
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external returns (address, bytes memory) {
        bytes memory wrapperData;
        for (uint256 i = 0; i < wrappers.length; i++) {
            wrapperData = abi.encodePacked(
                wrapperData,
                wrapperDatas[i],
                uint256(uint160(wrappers.length > i + 1 ? wrappers[i + 1] : cowSettlement))
            );
        }

        // Build the full calldata for wrapper1
        bytes memory settleCalldata =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        bytes memory fullCalldata = abi.encodePacked(settleCalldata, wrapperData);

        return (wrappers[0], fullCalldata);
    }
}
