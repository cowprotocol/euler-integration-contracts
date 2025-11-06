// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Signing} from "cow/mixins/GPv2Signing.sol";
import {GPv2Order} from "cow/libraries/GPv2Order.sol";
import {GPv2Trade, IERC20} from "cow/libraries/GPv2Trade.sol";

// Vendored and adapted from CoW Protocol contrats repo with minor modifications:
// - Use only `extractOrderUidParams`
// - Add `extractOrder` which basically does parameter shuffling
// - Modified Solidity version
// - Formatted code
// <https://github.com/euler-xyz/ethereum-vault-connector/blob/34bb788288a0eb0fbba06bc370cb8ca3dd42614e/test/unit/EthereumVaultConnector/Permit.t.sol#L68>

contract GPv2OrderHelper {
    using GPv2Order for bytes;

    function extractOrderUidParams(bytes calldata orderUid)
        external
        pure
        returns (bytes32 orderDigest, address owner, uint32 validTo)
    {
        return orderUid.extractOrderUidParams();
    }

    function extractOrder(GPv2Trade.Data calldata trade, IERC20[] calldata tokens)
        external
        pure
        returns (GPv2Order.Data memory extractedOrder, GPv2Signing.Scheme scheme)
    {
        GPv2Order.Data memory order;
        scheme = GPv2Trade.extractOrder(trade, tokens, order);
        return (order, scheme);
    }
}
