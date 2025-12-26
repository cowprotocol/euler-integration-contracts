// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";
import {IERC20} from "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice A contract for receiving funds from the CoW Settlement contract which can then be operated upon by a different contract in post (i.e. a wrapper)
/// @dev The contract has two associated accounts-- the OWNER, and the BENEFICIARY. Both associated accounts have the ability to execute token operations against this contract.
/// The purpose of the OWNER is to allow the wrapper to execute whatever operations it needs following a settlement contract operation without needing to store in the wrapper itself (ex. potentially intermingled with other user's funds) or the user's own wallet.
/// The purpose of the BENEFICIARY is to allow the ultimate holder of the funds to be able to access this contract in the case of trouble (ex. funds got stuck, etc.)
contract Inbox {
    using SafeERC20 for IERC20;

    address internal immutable OWNER;
    address internal immutable BENEFICIARY;

    error Unauthorized(address);

    constructor(address owner, address beneficiary) {
        OWNER = owner;
        BENEFICIARY = beneficiary;
    }

    /// @notice Transfers tokens from this contract to a recipient
    /// @param token The ERC20 token to transfer
    /// @param to The recipient address
    /// @param amount The amount to transfer
    function callTransfer(address token, address to, uint256 amount) external {
        require(msg.sender == OWNER || msg.sender == BENEFICIARY, Unauthorized(msg.sender));
        IERC20(token).safeTransfer(to, amount);
    }

    /// @notice Calls repay on a vault to repay debt from this contract's balance
    /// @param vault The vault contract to call repay on
    /// @param amount The amount to repay
    /// @param account The account to repay debt for
    function callVaultRepay(address vault, address asset, uint256 amount, address account) external {
        require(msg.sender == OWNER || msg.sender == BENEFICIARY, Unauthorized(msg.sender));
        IERC20(asset).forceApprove(vault, amount);
        IBorrowing(vault).repay(amount, account);
    }
}
