// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {IERC20} from "../../src/vendor/interfaces/IERC20.sol";

contract MilkSwap {
    mapping(address => uint256) public prices; // Price expressed in atoms of the quote per unit of the base token

    function setPrice(address token, uint256 price) external {
        prices[token] = price;
    }

    function getAmountOut(address tokenIn, address tokenOut, uint256 amountIn)
        external
        view
        returns (uint256 amountOut)
    {
        uint256 priceIn = prices[tokenIn];
        uint256 priceOut = prices[tokenOut];
        require(priceIn > 0, "tokenIn is not supported");
        require(priceOut > 0, "tokenOut is not supported");

        return (amountIn * priceIn / priceOut);
    }

    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        uint256 amountOut = this.getAmountOut(tokenIn, tokenOut, amountIn);

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);
    }
}
