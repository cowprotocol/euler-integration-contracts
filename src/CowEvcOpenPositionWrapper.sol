// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {ICowSettlement, CowWrapper} from "./CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";
import {CowEvcBaseWrapper} from "./CowEvcBaseWrapper.sol";

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
contract CowEvcOpenPositionWrapper is CowEvcBaseWrapper {
    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 constant DOMAIN_NAME = keccak256("CowEvcOpenPositionWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 constant DOMAIN_VERSION = keccak256("1");

    /// @dev A descriptive label for this contract, as required by CowWrapper
    string public override name = "Euler EVC - Open Position";

    /// @dev Emitted when a position is opened via this wrapper
    event CowEvcPositionOpened(
        address indexed owner,
        address account,
        address indexed collateralVault,
        address indexed borrowVault,
        uint256 collateralAmount,
        uint256 borrowAmount
    );

    constructor(address _evc, ICowSettlement _settlement)
        CowEvcBaseWrapper(_evc, _settlement, DOMAIN_NAME, DOMAIN_VERSION, 5)
    {
        PARAMS_SIZE =
        abi.encode(
            OpenPositionParams({
                owner: address(0),
                account: address(0),
                deadline: 0,
                collateralVault: address(0),
                borrowVault: address(0),
                collateralAmount: 0,
                borrowAmount: 0
            })
        )
        .length;
    }

    /// @notice The information necessary to open a debt position against an euler vault using collateral as backing.
    /// @dev This structure is used, combined with domain separator, to indicate a pre-approved hash.
    /// the `deadline` is used for deduplication checking, so be careful to ensure this value is unique.
    struct OpenPositionParams {
        /// @dev The ethereum address that has permission to operate upon the account
        address owner;

        /// @dev The subaccount to open the position on. Learn more about Euler subaccounts https://evc.wtf/docs/concepts/internals/sub-accounts
        address account;

        /// @dev A date by which this operation must be completed
        uint256 deadline;

        /// @dev The Euler vault to use as collateral
        address collateralVault;

        /// @dev The Euler vault to use as leverage
        address borrowVault;

        /// @dev The amount of collateral to import as margin. Set this to `0` if the vault already has margin collateral.
        uint256 collateralAmount;

        /// @dev The amount of debt to take out. The borrowed tokens will be converted to `collateralVault` tokens and deposited into the account.
        uint256 borrowAmount;
    }

    function _parseOpenPositionParams(bytes calldata wrapperData)
        internal
        view
        returns (OpenPositionParams memory params, bytes memory signature, bytes calldata remainingWrapperData)
    {
        (params, signature) = abi.decode(wrapperData, (OpenPositionParams, bytes));

        // Calculate consumed bytes for abi.encode(OpenPositionParams, bytes)
        // Structure:
        // - 32 bytes: offset to params (0x40)
        // - 32 bytes: offset to signature
        // - x bytes: params data (computed size in constructor to prevent errors)
        // - 32 bytes: signature length
        // - N bytes: signature data (padded to 32-byte boundary)
        uint256 consumed = PARAMS_SIZE + 64 + ((signature.length + 31) & ~uint256(31));

        remainingWrapperData = wrapperData[consumed:];
    }

    /// @notice Helper function to compute the hash that would be approved
    /// @param params The OpenPositionParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(OpenPositionParams memory params) external view returns (bytes32) {
        return _getApprovalHash(memoryLocation(params));
    }

    /// @inheritdoc CowWrapper
    function validateWrapperData(bytes calldata wrapperData) external view override {
        // Validate by attempting to parse the wrapper data
        // Will revert if the data is malformed
        _parseOpenPositionParams(wrapperData);
    }

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations to open a position
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing OpenPositionParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Decode wrapper data into OpenPositionParams
        (OpenPositionParams memory params, bytes memory signature,) = _parseOpenPositionParams(wrapperData);

        _invokeEvc(
            settleData,
            wrapperData,
            remainingWrapperData,
            memoryLocation(params),
            signature,
            params.owner,
            params.deadline
        );

        emit CowEvcPositionOpened(
            params.owner,
            params.account,
            params.collateralVault,
            params.borrowVault,
            params.collateralAmount,
            params.borrowAmount
        );
    }

    function getSignedCalldata(OpenPositionParams memory params) external view returns (bytes memory) {
        (IEVC.BatchItem[] memory items,) = _encodeBatchItemsBefore(memoryLocation(params));
        return abi.encodeCall(IEVC.batch, items);
    }

    function _encodeBatchItemsBefore(ParamsLocation paramsLocation)
        internal
        view
        override
        returns (IEVC.BatchItem[] memory items, bool needsPermission)
    {
        OpenPositionParams memory params = paramsFromMemory(paramsLocation);
        items = new IEVC.BatchItem[](4);

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

        needsPermission = true;
    }

    function _evcInternalSettle(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _next(settleData, remainingWrapperData);
    }

    function memoryLocation(OpenPositionParams memory params) internal pure returns (ParamsLocation location) {
        assembly ("memory-safe") {
            location := params
        }
    }

    function paramsFromMemory(ParamsLocation location) internal pure returns (OpenPositionParams memory params) {
        assembly {
            params := location
        }
    }
}
