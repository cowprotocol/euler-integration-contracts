// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;
pragma abicoder v2;

import {CowWrapper, CowSettlement} from "../src/vendor/CowWrapper.sol";

contract EmptyWrapper is CowWrapper {
    string public constant name = "Empty Wrapper";

    constructor(CowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData) internal override {
        _internalSettle(settleData, remainingWrapperData);
    }

    function parseWrapperData(bytes calldata wrapperData) external pure override returns (bytes calldata remainingWrapperData) {
        // EmptyWrapper doesn't consume any wrapper data
        return wrapperData;
    }
}
