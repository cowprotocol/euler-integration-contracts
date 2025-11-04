// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;
pragma abicoder v2;

import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";

contract EmptyWrapper is CowWrapper {
    string public override name = "Empty Wrapper";

    constructor(ICowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData) internal override {
        _internalSettle(settleData, remainingWrapperData);
    }
}
