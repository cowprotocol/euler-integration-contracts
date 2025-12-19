// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {ICowSettlement, CowWrapper} from "./CowWrapper.sol";
import {IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20Lib} from "euler-vault-kit/src/EVault/shared/lib/SafeERC20Lib.sol";
import {CowEvcBaseWrapper} from "./CowEvcBaseWrapper.sol";

import {ISignatureTransfer} from "euler-vault-kit/lib/permit2/src/interfaces/ISignatureTransfer.sol";

/// @title CowEvcClosePositionWrapper
/// @notice A specialized wrapper for closing leveraged positions with EVC
/// @dev This wrapper hardcodes the EVC operations needed to close a position:
///      1. Transfer the required collateral from the subaccount to the owner within the EVC batch so that the settlement contract can access (if required)
///      2. Execute settlement to acquire repayment assets
///      3. Repay debt and return remaining assets to the subaccount
/// @dev The settle call by this order should be performing the necessary swap
/// from collateralVault -> IERC20(borrowVault.asset()). The recipient of the
/// swap should be the owner of the subaccount. Following this, the account will repay the loan by leveraging an approval from the owner account in `helperRepay`.
/// The order should be of type GPv2Order.KIND_BUY to prevent excess from being sent to the contract.
/// If a full close is being performed, leave a small buffer for intrest accumultation, and the dust will
/// be returned to the owner's wallet.
contract CowEvcClosePositionWrapper is CowEvcBaseWrapper {
    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 constant DOMAIN_NAME = keccak256("CowEvcClosePositionWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 constant DOMAIN_VERSION = keccak256("1");

    bytes8 transient public subaccountTicker;

    ISignatureTransfer internal constant PERMIT2 =
        ISignatureTransfer(address(0x000000000022D473030F116dDEE9F6B43aC78BA3));


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
                maxRepayAmount: 0,
                kind: bytes32(0)
            })
        )
        .length;

        MAX_BATCH_OPERATIONS = 2;

        PARAMS_TYPE_HASH = keccak256(
            "ClosePositionParams(address owner,address account,uint256 deadline,address borrowVault,address collateralVault,uint256 collateralAmount,uint256 maxRepayAmount,bytes32 kind)"
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

        /// @dev The amount of collateral to swap from the collateral vault, in terms of collateral vault shares.
        /// This should be equal to `sellAmount` on the CoW order, and
        /// the full amount will be transferred from the wallet.
        /// In the case of KIND_BUY order, Any excess untraded for funds will be returned to the subaccount.
        uint256 collateralAmount;

        /// @dev In all cases, the maximum amount of debt to repay. For kind = KIND_BUY, this should be the same as `buyAmount` in the CoW order. For kind = KIND_SELL, this should be equal to or greater than `buyAmount`, . The actual repay amount is constrained by this value, the actual debt of the account, and the balance of the owner's wallet following the CoW trade. If the repay amount is greater than the actual debt, the full debt is repaid, and the remainder "dust" will be left in the owner account.
        uint256 maxRepayAmount;

        /// @dev Whether the `collateralAmount` or `maxRepayAmount` should be considered the exact trade amount on the CoW order. Either `GPv2Order.KIND_SELL` or `GPv2Order.KIND_BUY` respectively.
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
        (IEVC.BatchItem[] memory items,) = _encodeBatchItemsBefore(memoryLocation(params));
        return _encodePermitData(items, memoryLocation(params));
    }

    function _encodeBatchItemsBefore(ParamsLocation paramsLocation)
        internal
        view
        override
        returns (IEVC.BatchItem[] memory items, bool needsPermission)
    {
        ClosePositionParams memory params = paramsFromMemory(paramsLocation);
        items = new IEVC.BatchItem[](MAX_BATCH_OPERATIONS - 1);

        // 1. Transfer collateral to the owner
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(params.account),
            targetContract: params.collateralVault,
            value: 0,
            data: abi.encodeCall(IERC20.transfer, (params.owner, params.collateralAmount))
        });

        needsPermission = true;
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
            params.maxRepayAmount,
            params.kind
        );
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) internal override {
        (ClosePositionParams memory params, bytes memory signature) = _parseClosePositionParams(wrapperData);

        uint256 balanceBefore;
        if (params.account != params.owner) {
            // the balance before would have been the current balance without the collateral amount (which was transferred from the subaccount)
            balanceBefore = IERC20(params.collateralVault).balanceOf(params.owner) - params.collateralAmount;
        }

        // Use CowWrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _next(settleData, remainingWrapperData);

        if (params.kind == KIND_BUY && params.account != params.owner) {
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

        IERC20 asset = IERC20(IERC4626(params.borrowVault).asset());

        uint256 debtAmount = IBorrowing(params.borrowVault).debtOf(params.account);

        // what is the maximum amount of debt that can
        // be repaid from the owner account?
        uint256 repayAmount = asset.balanceOf(params.owner);

        // we can't repay more than the available debt amount
        if (repayAmount > debtAmount) {
            // the user intends to repay all their debt. we will revert if their balance is not sufficient.
            repayAmount = debtAmount;
        }

        // we also can't repay more than the user specified max repayment amount
        if (repayAmount > params.maxRepayAmount) {
            repayAmount = params.maxRepayAmount;
        }

        // pull funds from the user (they should have approved spending by this contract)
        SafeERC20Lib.safeTransferFrom(asset, params.owner, address(this), repayAmount, address(0));

        // repay what was requested on the vault
        safeApprove(asset, params.borrowVault, repayAmount);
        IBorrowing(params.borrowVault).repay(repayAmount, params.account);
        safeApprove(asset, params.borrowVault, 0);
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

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silents catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We cannot use {Address-functionCall} here since this should return false
        // and not revert is the subcall reverts.

        (bool success, bytes memory returndata) = address(token).call(data);
        return success && (returndata.length == 0 || abi.decode(returndata, (bool))) && address(token).code.length > 0;
    }

    error SafeERC20FailedOperation(address);

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(address token, bytes memory data) private returns (bytes memory) {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address-functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        (bool success, bytes memory returndata) = token.call(data);
        if (!success) {
            revert("");
        } else {
            // only check if target is a contract if the call was successful and the return data is empty
            // otherwise we already know that it was a contract
            if (returndata.length == 0 && token.code.length == 0) {
                revert("");
            }
            return returndata;
        }

        if (returndata.length != 0 && !abi.decode(returndata, (bool))) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Mostly copied from OpenZeppelin SafeERC20. Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     */
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(address(token), abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(address(token), approvalCall);
        }
    }
}
