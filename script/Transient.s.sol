// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {Counter} from "../src/Counter.sol";

import "forge-std/console.sol";

contract TransientStorage {
    uint256 public transient val;

    function setTrans(uint256 v) external {
        val = v;
    }

    function getTrans() external returns (uint256) {
        return val;
    }
}

contract TransientScript is Script {
    Counter public counter;

    function setUp() public {}

    function run() public {
        TransientStorage t = new TransientStorage();

        vm.startBroadcast();

        console.log(t.val());

        t.setTrans(420);

        console.log(t.val());

        console.log(t.getTrans());

        vm.stopBroadcast();
    }
}
