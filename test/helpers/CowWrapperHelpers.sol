// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {CowSettlement, ICowWrapper, CowAuthentication} from "src/vendor/CowWrapper.sol";

library CowWrapperHelpers {
    struct SettleCall {
        address[] tokens;
        uint256[] clearingPrices;
        CowSettlement.CowTradeData[] trades;
        CowSettlement.CowInteractionData[][3] interactions;
    }

    /**
     * @dev This function is intended for testing purposes and is not memory efficient.
     * @param wrappers Array of wrapper addresses to chain together
     * @param wrapperDatas Array of wrapper-specific data for each wrapper
     * @param cowSettlement The settlement contract address (unused, kept for backwards compatibility)
     * @param settlement The settlement call parameters
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
                uint16(wrapperDatas[i].length),
                wrapperDatas[i]
            );
            // Include the next wrapper address if there is one
            if (wrappers.length > i + 1) {
                wrapperData = abi.encodePacked(wrapperData, wrappers[i + 1]);
            }
            // For the last wrapper, don't add anything - the static SETTLEMENT will be called automatically
        }

        // Build the settle calldata
        bytes memory settleData =
            abi.encodeWithSelector(CowSettlement.settle.selector, settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions);

        // Encode the wrappedSettle call
        fullCalldata = abi.encodeWithSelector(ICowWrapper.wrappedSettle.selector, settleData, wrapperData);

        return (wrappers[0], fullCalldata);
    }
}
