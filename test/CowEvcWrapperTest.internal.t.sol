// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import "../src/CowEvcWrapper.sol";
import "forge-std/Test.sol";

contract CowEvcWrapperTest is CowEvcWrapper, Test {

    constructor() public CowEvcWrapper(address(0), payable(0)) {
    }

    function testCopyAndReadFromTransientStorage() external {
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(1234),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (address(3456), address(4567), 0, 0, block.timestamp, 0, "82828282828282828288888888888888888888888888888888888888888888888888888888888888888888888222222222222222222222222", ""))
        });


        _copyToTransientStorage(items, "testing");

        IEVC.BatchItem[] memory loadedItems = _readFromTransientStorage("testing");

        assertEq(loadedItems.length, 1);
        assertEq(items[0].targetContract, loadedItems[0].targetContract);
        assertEq(items[0].data.length, loadedItems[0].data.length);
    }
}
