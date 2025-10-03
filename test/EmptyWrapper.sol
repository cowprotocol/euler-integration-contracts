// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;
pragma abicoder v2;

import "../src/vendor/CowWrapper.sol";

contract EmptyWrapper is CowWrapper {
    constructor(GPv2Authentication authenticator_) CowWrapper(authenticator_) {}

    function _wrap(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrappedData
    ) internal override {
        _internalSettle(tokens, clearingPrices, trades, interactions, wrappedData);
    }
}
