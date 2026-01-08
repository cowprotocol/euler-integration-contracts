// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20Lib} from "euler-vault-kit/src/EVault/shared/lib/SafeERC20Lib.sol";

contract MilkSwap {
    mapping(address => uint256) public prices; // Price expressed in atoms of the quote per unit of the base token

    function setPrice(IERC20 token, uint256 price) external {
        prices[address(token)] = price;
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

    function swap(IERC20 tokenIn, IERC20 tokenOut, uint256 amountIn) external {
        uint256 amountOut = this.getAmountOut(address(tokenIn), address(tokenOut), amountIn);

        SafeERC20Lib.safeTransferFrom(tokenIn, msg.sender, address(this), amountIn, address(0));
        SafeERC20Lib.safeTransfer(tokenOut, msg.sender, amountOut);
    }
}
