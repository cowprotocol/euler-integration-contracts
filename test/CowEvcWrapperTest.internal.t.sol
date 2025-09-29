// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.23;

import "../src/CowEvcWrapper.sol";
import "forge-std/Test.sol";

contract CowEvcWrapperTest is CowEvcWrapper, Test {
    constructor() public CowEvcWrapper(address(0), payable(0)) {}
}
