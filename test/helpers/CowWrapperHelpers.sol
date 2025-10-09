// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {IERC20, GPv2Trade, GPv2Interaction, GPv2Authentication} from "cow/GPv2Settlement.sol";

import {CowSettlement, ICowWrapper} from "src/vendor/CowWrapper.sol";

library CowWrapperHelpers {
    struct SettleCall {
        IERC20[] tokens;
        uint256[] clearingPrices;
        GPv2Trade.Data[] trades;
        GPv2Interaction.Data[][3] interactions;
    }

    /**
     * @dev This function is intended for testing purposes and is not memory efficient.
     */
    function encodeWrapperCall(
        address[] calldata wrappers,
        bytes[] calldata wrapperDatas,
        address cowSettlement,
        SettleCall calldata settlement
    ) external returns (address target, bytes memory fullCalldata) {
        // Build the wrapper data chain
        bytes memory wrapperData;
        for (uint256 i = 0; i < wrappers.length; i++) {
            wrapperData = abi.encodePacked(
                wrapperData,
                wrapperDatas[i],
                (wrappers.length > i + 1 ? wrappers[i + 1] : cowSettlement)
            );
        }

        // Build the settle calldata
        bytes memory settleData =
            abi.encodeWithSelector(CowSettlement.settle.selector, settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions);

        // Encode the wrappedSettle call
        fullCalldata = abi.encodeWithSelector(ICowWrapper.wrappedSettle.selector, settleData, wrapperData);

        return (wrappers[0], fullCalldata);
    }
}
