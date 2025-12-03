// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";

contract EmptyWrapper is CowWrapper {
    string public override name = "Empty Wrapper";

    constructor(ICowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData) internal override {
        _next(settleData, remainingWrapperData);
    }

    function parseWrapperData(bytes calldata wrapperData)
        external
        pure
        override
        returns (bytes calldata remainingWrapperData)
    {
        // EmptyWrapper doesn't consume any wrapper data
        return wrapperData;
    }
}
