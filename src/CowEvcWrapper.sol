// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";
//import {IGPv2Settlement, GPv2Interaction} from "./vendor/interfaces/IGPv2Settlement.sol";
import {IGPv2Authentication} from "./vendor/interfaces/IGPv2Authentication.sol";

import {GPv2Signing, GPv2Trade, GPv2Order} from "cow/mixins/GPv2Signing.sol";
import {GPv2Interaction} from "cow/libraries/GPv2Interaction.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

import {Borrower, IERC20, IFlashLoanRouter} from "flash-loan-router/mixin/Borrower.sol";

/// @title CowEvcWrapper
/// @notice A wrapper around the EVC that allows for settlement operations
contract CowEvcWrapper is Borrower, GPv2Signing {
    IEVC public immutable EVC;

    address public transient borrower;

    mapping(bytes32 => IEVC.BatchItem[]) private postActions;

    error Unauthorized(address msgSender);
    error NoReentrancy();
    error MultiplePossibleReceivers(
        address resolvedVault, address resolvedSender, address secondVault, address secondSender
    );

    error NotEVCSettlement();

    constructor(address _evc, IFlashLoanRouter _flashLoanRouter) Borrower(_flashLoanRouter) {
        EVC = IEVC(_evc);
    }

    struct ResolvedValues {
        address vault;
        address sender;
        uint256 minAmount;
    }

    // TODO: need to set up some sort of signing/permit here because this is malleable by solver
    function setBorrower(address _borrower) external {
        borrower = _borrower;
    }

    /// @notice Implementation of Borrower.triggerFlashLoan, which allows for a euler position to be opened
    /// PRIOR to calling this function, `setOperator` must be called to allow this function to execute on behalf of the `borrower` set in `setBorrower`.
    function triggerFlashLoan(address lender, IERC20 token, uint256 amount, bytes calldata callBackData)
        internal
        override
    {
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](3);

        // this call needs to happen before calling this function because we dont know what the borrowed collateral is
        //items[0] = IEVC.BatchItem({
        //    onBehalfOfAccount: address(0),
        //    targetContract: address(evc),
        //    value: 0,
        //    data: abi.encodeCall(IEVC.enableCollateral, (borrower, ???))
        //});
        //items[0] = IEVC.BatchItem({
        //    onBehalfOfAccount: address(0),
        //    targetContract: address(EVC),
        //    value: 0,
        //    data: abi.encodeCall(IEVC.enableController, (borrower, lender))
        //});

        // the below call requires operator permissions in order to borrow on behalf of account
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: borrower,
            targetContract: address(lender),
            value: 0,
            data: abi.encodeCall(IBorrowing.borrow, (amount, address(settlementContract)))
        });

        // this will call settle
        // the settlement shuold be borrowed token -> euler vault token, into the user's account
        items[2] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.callback, (callBackData))
        });

        // Execute all items in a single batch
        EVC.batch(items);
    }

    function callback(bytes calldata callBackData) external {
        flashLoanCallBack(callBackData);
    }
}
