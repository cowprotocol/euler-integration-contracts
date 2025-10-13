// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, CowAuthentication, CowSettlement} from "./vendor/CowWrapper.sol";
import {IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import "forge-std/console.sol";

/// @title CowEvcClosePositionWrapper
/// @notice A specialized wrapper for closing leveraged positions with EVC
/// @dev This wrapper hardcodes the EVC operations needed to close a position:
///      1. Execute settlement to acquire repayment assets
///      2. Repay debt and return remaining assets to user
/// @dev The settle call by this order should be performing the necessary swap
/// from collateralVault -> IERC20(borrowVault.asset()). The recipient of the 
/// swap should *THIS* contract so that it can repay on behalf of the user. Furthermore,
/// the order should be of type GPv2Order.KIND_BUY to prevent excess from being sent to the contract.
/// If a full close is being performed, leave a small buffer for intrest accumultation, and the dust will
/// be returned to the user's wallet.
contract CowEvcClosePositionWrapper is CowWrapper {
    IEVC public immutable EVC;

    /// @notice Tracks the number of times this wrapper has been called
    uint256 public transient depth;
    /// @notice Tracks the number of times `evcInternalSettle` has been called
    uint256 public transient settleCalls;

    uint256 public immutable nonceNamespace;

    error Unauthorized(address msgSender);
    error NotEVCSettlement();
    error InsufficientRepaymentAsset(address vault, uint256 balanceAmount, uint256 repayAmount);

    constructor(address _evc, CowAuthentication _authentication) CowWrapper(_authentication) {
        EVC = IEVC(_evc);
        nonceNamespace = uint256(uint160(address(this)));
    }

    struct ClosePositionParams {
        address user;
        uint256 deadline;
        address borrowVault;
        address collateralVault;
        uint256 maxRepayAmount; // Use a number greater than the actual debt to repay full debt
    }

    function _parseClosePositionParams(bytes calldata wrapperData) internal pure returns (ClosePositionParams memory params, bytes memory signature, bytes calldata remainingWrapperData) {
        (params, signature) = abi.decode(wrapperData, (ClosePositionParams, bytes));

        // Calculate consumed bytes for abi.encode(ClosePositionParams, bytes)
        // Structure:
        // - 32 bytes: offset to params (0x40)
        // - 32 bytes: offset to signature
        // - 160 bytes: params data (5 fields × 32 bytes)
        // - 32 bytes: signature length
        // - N bytes: signature data (padded to 32-byte boundary)
        // We can just math this out
        uint256 consumed = 160 + 64 + ((signature.length + 31) / 32 ) * 32;

        remainingWrapperData = wrapperData[consumed:];
    }

    function parseWrapperData(bytes calldata wrapperData) external pure override returns (bytes calldata remainingWrapperData) {
        (, , remainingWrapperData) = _parseClosePositionParams(wrapperData);
    }

    function getSignedCalldata(ClosePositionParams memory params) external view returns (bytes memory) {
        return _getSignedCalldata(params);
    }

    function _getSignedCalldata(ClosePositionParams memory params) internal view returns (bytes memory) {
        // get current user debt, and find out if we are repaying all
        uint256 debtAmount = IBorrowing(params.borrowVault).debtOf(params.user);
        bool repayAll = params.maxRepayAmount >= debtAmount;

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](repayAll ? 4 : 3);

        // 1. Set account operator to allow this contract to act on behalf of user
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.setAccountOperator, (params.user, address(this), true))
        });

        // 2. Repay debt and return remaining assets
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: params.user,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.helperRepayAndReturn, (params.borrowVault, params.user, params.maxRepayAmount, repayAll))
        });

        // 3. If we are repaying all, we should disable the collateral from the user's account
        if (repayAll) {
            items[2] = IEVC.BatchItem({
                onBehalfOfAccount: address(0),
                targetContract: address(EVC),
                value: 0,
                data: abi.encodeCall(IEVC.disableCollateral, (params.user, params.collateralVault))
            });
        }

        // 4. Revoke operator permission
        items[repayAll ? 3 : 2] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.setAccountOperator, (params.user, address(this), false))
        });

        return abi.encodeCall(IEVC.batch, (items));
    }

    // helper function to execute repay
    function helperRepayAndReturn(address vault, address beneficiary, uint256 maxRepay, bool repayAll) external {
        IERC20 asset = IERC20(IERC4626(vault).asset());

        // the settlement contract should have sent us `maxRepay` money
        // if we dont have enough money, then either:
        // 1. the CowOrder was not configured to correctly give us enough money
        // 2. Somebody else using this wrapper (nesting the wrappers) did #1 (and the solver borked up)
        require(asset.balanceOf(address(this)) >= maxRepay, InsufficientRepaymentAsset(vault, asset.balanceOf(address(this)), maxRepay));

        asset.approve(vault, type(uint256).max);
        uint256 actualRepay = IBorrowing(vault).repay(repayAll ? type(uint256).max : maxRepay, beneficiary);

        // transfer any remaining dust back to the user
        if (actualRepay < maxRepay) {
            asset.transfer(beneficiary, maxRepay - actualRepay);
        }
    }

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations to close a position
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing ClosePositionParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData) internal override {
        depth = depth + 1;

        // Decode wrapper data into ClosePositionParams
        ClosePositionParams memory params;
        bytes memory signature;
        (params, signature, wrapperData) = _parseClosePositionParams(wrapperData);

        // Build the EVC batch items for closing a position
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);

        // 1. Settlement call
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (settleData, wrapperData))
        });

        // 2. Acquire operator permissions and execute signed actions (repay, disable collateral if needed, revoke operator)
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (
                params.user,
                address(this),
                uint256(nonceNamespace),
                EVC.getNonce(bytes19(bytes20(params.user)), nonceNamespace),
                params.deadline,
                0,
                _getSignedCalldata(params),
                signature
            ))
        });

        // 3. Account status check (automatically done by EVC at end of batch)
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);
    }

    /// @notice Internal settlement function called by EVC
    function evcInternalSettle(bytes calldata settleData, bytes calldata wrapperData) external payable {
        if (msg.sender != address(EVC)) {
            revert Unauthorized(msg.sender);
        }

        // depth should be > 0 (actively wrapping a settle call) and no settle call should have been performed yet
        if (depth == 0 || settleCalls != 0) {
            revert Unauthorized(address(0));
        }

        settleCalls = settleCalls + 1;

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _internalSettle(settleData, wrapperData);
    }
}
