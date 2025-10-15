// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, CowAuthentication} from "./vendor/CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

import "forge-std/console.sol";

/// @title CowEvcOpenPositionWrapper
/// @notice A specialized wrapper for opening leveraged positions with EVC
/// @dev This wrapper hardcodes the EVC operations needed to open a position:
///      1. Enable collateral vault
///      2. Enable controller (borrow vault)
///      3. Deposit collateral
///      4. Borrow assets
/// @dev The settle call by this order should be performing the necessary swap
/// from IERC20(borrowVault.asset()) -> collateralVault. The recipient of the
/// swap should be the `owner` (not this contract). Furthermore, the buyAmountIn should
/// be the same as `maxRepayAmount`.
contract CowEvcOpenPositionWrapper is CowWrapper {
    IEVC public immutable EVC;

    /// @notice Tracks the number of times this wrapper has been called
    uint256 public transient depth;
    /// @notice Tracks the number of times `evcInternalSettle` has been called
    uint256 public transient settleCalls;

    uint256 public immutable nonceNamespace;

    error Unauthorized(address msgSender);
    error NotEVCSettlement();

    constructor(address _evc, CowAuthentication _authentication) CowWrapper(_authentication) {
        EVC = IEVC(_evc);
        nonceNamespace = uint256(uint160(address(this)));
    }

    struct OpenPositionParams {
        address owner;
        address account;
        uint256 deadline;
        address collateralVault;
        address borrowVault;
        uint256 collateralAmount;
        uint256 borrowAmount;
    }

    function _parseOpenPositionParams(bytes calldata wrapperData) internal pure returns (OpenPositionParams memory params, bytes memory signature, bytes calldata remainingWrapperData) {
        (params, signature) = abi.decode(wrapperData, (OpenPositionParams, bytes));

        // Calculate consumed bytes for abi.encode(OpenPositionParams, bytes)
        // Structure:
        // - 32 bytes: offset to params (0x40)
        // - 32 bytes: offset to signature
        // - 224 bytes: params data (7 fields × 32 bytes)
        // - 32 bytes: signature length
        // - N bytes: signature data (padded to 32-byte boundary)
        // We can just math this out
        uint256 consumed = 224 + 64 + ((signature.length + 31) / 32 ) * 32;

        remainingWrapperData = wrapperData[consumed:];
    }

    function parseWrapperData(bytes calldata wrapperData) external pure override returns (bytes calldata remainingWrapperData) {
        (, , remainingWrapperData) = _parseOpenPositionParams(wrapperData);
    }

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations to open a position
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing OpenPositionParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData) internal override {
        depth = depth + 1;

        // Decode wrapper data into OpenPositionParams
        OpenPositionParams memory params;
        bytes memory signature;
        (params, signature, wrapperData) = _parseOpenPositionParams(wrapperData);

        // Build the EVC batch items for opening a position
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);

        // 1. Acquire operator permissions
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (
                params.owner,
                address(this),
                uint256(nonceNamespace),
                EVC.getNonce(bytes19(bytes20(params.owner)), nonceNamespace),
                params.deadline,
                0,
                _getSignedCalldata(params),
                signature
            ))
        });

        // 2. Settlement call
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (settleData, wrapperData))
        });

        // 3. Account status check (automatically done by EVC at end of batch)
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);
    }

    function getSignedCalldata(OpenPositionParams memory params) external view returns (bytes memory) {
        return _getSignedCalldata(params);
    }

    function _getSignedCalldata(OpenPositionParams memory params) internal view returns (bytes memory) {
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](4);

        // 1. Enable collateral
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.enableCollateral, (params.account, params.collateralVault))
        });

        // 2. Enable controller (borrow vault)
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.enableController, (params.account, params.borrowVault))
        });

        // 3. Deposit collateral
        items[2] = IEVC.BatchItem({
            onBehalfOfAccount: params.owner,
            targetContract: params.collateralVault,
            value: 0,
            data: abi.encodeCall(IERC4626.deposit, (params.collateralAmount, params.account))
        });

        // 4. Borrow assets
        items[3] = IEVC.BatchItem({
            onBehalfOfAccount: params.account,
            targetContract: params.borrowVault,
            value: 0,
            data: abi.encodeCall(IBorrowing.borrow, (params.borrowAmount, params.owner))
        });

        return abi.encodeCall(IEVC.batch, (items));
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
