// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;
pragma abicoder v2;

import "../src/vendor/CowWrapper.sol";

contract EmptyWrapper is CowWrapper {
    constructor(CowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(
        bytes calldata settleData,
        bytes calldata wrappedData
    ) internal override {
        _internalSettle(settleData, wrappedData);
    }

    function parseWrapperData(bytes calldata wrapperData) external pure override returns (bytes calldata remainingWrapperData) {
        // EmptyWrapper doesn't consume any wrapper data
        return wrapperData;
    }
}
