// SPDX-License-Identifier: LGPL-3.0-or-later
pragma solidity ^0.8.0;

/// @title Gnosis Protocol v2 Trade Library
/// @author Gnosis Developers
/// @notice Vendored from https://github.com/cowprotocol/contracts/blob/main/src/contracts/libraries/GPv2Trade.sol
/// Only includes the minimal subset needed for testing

import {GPv2Order} from "./GPv2Order.sol";

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

library GPv2Trade {
    using GPv2Order for bytes;

    /// @dev A struct representing a trade to be executed as part of a GPv2
    /// settlement.
    struct Data {
        uint256 sellTokenIndex;
        uint256 buyTokenIndex;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        uint256 flags;
        uint256 executedAmount;
        bytes signature;
    }

    /// @dev Extracts the order data and signing scheme for the specified trade.
    ///
    /// @param trade The trade data from the settlement.
    /// @param tokens The list of tokens included in the settlement.
    /// @param order The memory location to extract the order data to.
    function extractOrder(Data calldata trade, IERC20[] calldata tokens, GPv2Order.Data memory order)
        internal
        pure
        returns (GPv2Signing.Scheme scheme)
    {
        order.sellToken = address(tokens[trade.sellTokenIndex]);
        order.buyToken = address(tokens[trade.buyTokenIndex]);
        order.receiver = trade.receiver;
        order.sellAmount = trade.sellAmount;
        order.buyAmount = trade.buyAmount;
        order.validTo = trade.validTo;
        order.appData = trade.appData;
        order.feeAmount = trade.feeAmount;

        // NOTE: The remaining order fields are decoded from the trade flags.
        uint256 flags = trade.flags;
        order.kind = (flags & 0x01 == 0) ? GPv2Order.KIND_SELL : GPv2Order.KIND_BUY;
        order.partiallyFillable = (flags & 0x02 != 0);
        order.sellTokenBalance = (flags & 0x08 == 0) ? GPv2Order.BALANCE_ERC20 : bytes32(uint256(0x01));
        order.buyTokenBalance = (flags & 0x10 == 0) ? GPv2Order.BALANCE_ERC20 : bytes32(uint256(0x02));

        // NOTE: The signing scheme is also encoded in the trade flags.
        scheme = GPv2Signing.Scheme(flags >> 8);
    }
}

library GPv2Signing {
    /// @dev An enum describing the signing scheme used for an order signature.
    enum Scheme {
        Eip712,
        EthSign,
        Eip1271,
        PreSign
    }
}
