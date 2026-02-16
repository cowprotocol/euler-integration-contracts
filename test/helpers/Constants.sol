// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

library Constants {
    bytes32 public constant EIP712_DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
}
