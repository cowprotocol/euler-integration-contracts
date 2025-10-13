// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;
pragma abicoder v2;

import "../src/vendor/CowWrapper.sol";

contract EmptyWrapper is CowWrapper {
    constructor(CowAuthentication authenticator_) CowWrapper(authenticator_) {}

    function _wrap(
        bytes calldata settleData,
        bytes calldata wrappedData
    ) internal override {
        _internalSettle(settleData, wrappedData);
    }
}
