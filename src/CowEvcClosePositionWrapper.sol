// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {ICowSettlement, CowWrapper} from "./CowWrapper.sol";
import {IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20Lib} from "euler-vault-kit/src/EVault/shared/lib/SafeERC20Lib.sol";
import {CowEvcBaseWrapper} from "./CowEvcBaseWrapper.sol";

/// @title CowEvcClosePositionWrapper
/// @notice A specialized wrapper for closing leveraged positions with EVC
/// @dev This wrapper hardcodes the EVC operations needed to close a position:
///      1. Execute settlement to acquire repayment assets
///      2. Repay debt and return remaining assets to user
/// @dev The settle call by this order should be performing the necessary swap
/// from collateralVault -> IERC20(borrowVault.asset()). The recipient of the
/// swap should *THIS* contract so that it can repay on behalf of the owner. Furthermore,
/// the order should be of type GPv2Order.KIND_BUY to prevent excess from being sent to the contract.
/// If a full close is being performed, leave a small buffer for intrest accumultation, and the dust will
/// be returned to the owner's wallet.
contract CowEvcClosePositionWrapper is CowEvcBaseWrapper {
    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 constant DOMAIN_NAME = keccak256("CowEvcClosePositionWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 constant DOMAIN_VERSION = keccak256("1");

    /// @dev A descriptive label for this contract, as required by CowWrapper
    string public override name = "Euler EVC - Close Position";

    /// @dev Emitted when a position is closed via this wrapper
    event CowEvcPositionClosed(
        address indexed owner,
        address account,
        address indexed borrowVault,
        address indexed collateralVault,
        uint256 collateralAmount,
        uint256 repayAmount,
        bytes32 kind
    );

    constructor(address _evc, ICowSettlement _settlement)
        CowEvcBaseWrapper(_evc, _settlement, DOMAIN_NAME, DOMAIN_VERSION)
    {
        PARAMS_SIZE =
        abi.encode(
            ClosePositionParams({
                owner: address(0),
                account: address(0),
                deadline: 0,
                borrowVault: address(0),
                collateralVault: address(0),
                collateralAmount: 0,
                repayAmount: 0,
                kind: bytes32(0)
            })
        )
        .length;

        MAX_BATCH_OPERATIONS = 2;

        PARAMS_TYPE_HASH = keccak256(
            "ClosePositionParams(address owner,address account,uint256 deadline,address borrowVault,address collateralVault,uint256 collateralAmount,uint256 repayAmount,bytes32 kind)"
        );
    }

    /// @notice The information necessary to close a debt position against an euler vault by repaying debt and returning collateral
    /// @dev This structure is used, combined with domain separator, to indicate a pre-approved hash.
    /// the `deadline` is used for deduplication checking, so be careful to ensure this value is unique.
    struct ClosePositionParams {
        /// @dev The ethereum address that has permission to operate upon the account
        address owner;

        /// @dev The subaccount to close the position on. Learn more about Euler subaccounts https://evc.wtf/docs/concepts/internals/sub-accounts
        address account;

        /// @dev A date by which this operation must be completed
        uint256 deadline;

        /// @dev The Euler vault from which debt was borrowed
        address borrowVault;

        /// @dev The Euler vault used as collateral
        address collateralVault;

        /// @dev The amount of collateral to swap from the collateral vault
        uint256 collateralAmount;

        /// @dev The amount of debt to repay. If greater than the actual debt, the full debt is repaid
        uint256 repayAmount;

        /// @dev Whether the `collateralAmount` or `repayAmount` is the exact amount. Either `GPv2Order.KIND_BUY` or `GPv2Order.KIND_SELL`
        bytes32 kind;
    }

    function _parseClosePositionParams(bytes calldata wrapperData)
        internal
        pure
        returns (ClosePositionParams memory params, bytes memory signature)
    {
        (params, signature) = abi.decode(wrapperData, (ClosePositionParams, bytes));
    }

    /// @notice Helper function to compute the hash that would be approved
    /// @param params The ClosePositionParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(ClosePositionParams memory params) external view returns (bytes32) {
        return _getApprovalHash(memoryLocation(params));
    }

    /// @inheritdoc CowWrapper
    function validateWrapperData(bytes calldata wrapperData) external pure override {
        // Validate by attempting to parse the wrapper data
        // Will revert if the data is malformed
        _parseClosePositionParams(wrapperData);
    }

    /// @notice Called by an offchain process to determine what data should be signed in a call to `wrappedSettle`.
    /// @param params The parameters object provided as input to the wrapper
    /// @return The `EVC` call that would be submitted to `EVC.permit`. This would need to be signed as documented https://evc.wtf/docs/concepts/internals/permit.
    function encodePermitData(ClosePositionParams memory params) external view returns (bytes memory) {
        (IEVC.BatchItem[] memory items,) = _encodeBatchItemsAfter(memoryLocation(params));
        return _encodePermitData(items, memoryLocation(params));
    }

    function _encodeBatchItemsAfter(ParamsLocation paramsLocation)
        internal
        view
        override
        returns (IEVC.BatchItem[] memory items, bool needsPermission)
    {
        ClosePositionParams memory params = paramsFromMemory(paramsLocation);
        items = new IEVC.BatchItem[](1);

        // 1. Repay debt and return remaining assets
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: params.account,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.helperRepay, (params.borrowVault, params.owner, params.account))
        });

        needsPermission = true;
    }

    /// @notice Called by the EVC after a CoW swap is completed to repay the user's debt. Will use all available collateral in the user's account to do so.
    /// @param vault The Euler vault in which the repayment should be made
    /// @param owner The owner associated with the given account. This the owner is used to provide the funds for the repayment.
    /// @param account The subaccount that should be receiving the repayment of debt
    function helperRepay(address vault, address owner, address account) external {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        (address onBehalfOfAccount,) = EVC.getCurrentOnBehalfOfAccount(address(0));
        require(onBehalfOfAccount == account, Unauthorized(onBehalfOfAccount));

        // Subaccounts in the EVC can be any account that shares the highest 19 bits as the owner.
        // Here we verify that the subaccount address has been specified as expected.
        // This is a really important security check because without verifying the subaccount,
        // any user could potentially repay
        require(bytes19(bytes20(owner)) == bytes19(bytes20(account)), SubaccountMustBeControlledByOwner(account, owner));

        IERC20 asset = IERC20(IERC4626(vault).asset());

        uint256 debtAmount = IBorrowing(vault).debtOf(account);

        // repay as much debt as we can
        uint256 repayAmount = asset.balanceOf(owner);
        if (repayAmount > debtAmount) {
            // the user intends to repay all their debt. we will revert if their balance is not sufficient.
            repayAmount = debtAmount;
        }

        // pull funds from the user (they should have approved spending by this contract)
        SafeERC20Lib.safeTransferFrom(asset, owner, address(this), repayAmount, address(0));

        // repay what was requested on the vault
        asset.approve(vault, repayAmount);
        IBorrowing(vault).repay(repayAmount, account);
    }

    /// @notice Implementation of CowWrapper._wrap - executes EVC operations to close a position
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing ClosePositionParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Decode wrapper data into ClosePositionParams
        (ClosePositionParams memory params, bytes memory signature) = _parseClosePositionParams(wrapperData);

        _invokeEvc(
            settleData,
            wrapperData,
            remainingWrapperData,
            memoryLocation(params),
            signature,
            params.owner,
            params.deadline
        );

        emit CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            params.repayAmount,
            params.kind
        );
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) internal override {
        (ClosePositionParams memory params,) = _parseClosePositionParams(wrapperData);
        // If a subaccount is being used, we need to transfer the required amount of collateral for the trade into the owner's wallet.
        // This is required becuase the settlement contract can only pull funds from the wallet that signed the transaction.
        // Since its not possible for a subaccount to sign a transaction due to the private key not existing and their being no
        // contract deployed to the subaccount address, transferring to the owner's account is the only option.
        // Additionally, we don't transfer this collateral directly to the settlement contract because the settlement contract
        // requires receiving of funds from the user's wallet, and cannot be put in the contract in advance.
        uint256 balanceBefore;
        if (params.owner != params.account) {
            // Subaccounts in the EVC can be any account that shares the highest 19 bits as the owner.
            // Here we briefly verify that the subaccount address has been specified as expected.
            require(
                bytes19(bytes20(params.owner)) == bytes19(bytes20(params.account)),
                SubaccountMustBeControlledByOwner(params.account, params.owner)
            );

            uint256 transferAmount = params.collateralAmount;

            if (params.kind == KIND_BUY) {
                // transfer the full balance from the subaccount to avoid price calculation
                transferAmount = IERC20(params.collateralVault).balanceOf(params.account);
                balanceBefore = IERC20(params.collateralVault).balanceOf(params.owner);
            }

            SafeERC20Lib.safeTransferFrom(
                IERC20(params.collateralVault), params.account, params.owner, transferAmount, address(0)
            );
        }

        // Use CowWrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _next(settleData, remainingWrapperData);

        if (params.kind == KIND_BUY) {
            // return any remainder to the subaccount
            uint256 balanceAfter = IERC20(params.collateralVault).balanceOf(params.owner);

            if (balanceAfter > balanceBefore) {
                SafeERC20Lib.safeTransferFrom(
                    IERC20(params.collateralVault),
                    params.owner,
                    params.account,
                    balanceAfter - balanceBefore,
                    address(0)
                );
            }
        }
    }

    function memoryLocation(ClosePositionParams memory params) internal pure returns (ParamsLocation location) {
        assembly ("memory-safe") {
            location := params
        }
    }

    function paramsFromMemory(ParamsLocation location) internal pure returns (ClosePositionParams memory params) {
        assembly {
            params := location
        }
    }
}
