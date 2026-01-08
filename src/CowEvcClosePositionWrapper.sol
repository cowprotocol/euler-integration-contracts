// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {Create2} from "openzeppelin-contracts/contracts/utils/Create2.sol";

import {ICowSettlement, CowWrapper} from "./CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20, IERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {CowEvcBaseWrapper} from "./CowEvcBaseWrapper.sol";
import {Inbox} from "./Inbox.sol";

/// @title CowEvcClosePositionWrapper
/// @notice A specialized wrapper for closing leveraged positions with EVC
/// @dev This wrapper hardcodes the EVC operations needed to close a position:
///      1. Transfer the required collateral from the subaccount to the owner within the EVC batch so that the settlement contract can access (if required)
///      2. Execute settlement to acquire repayment assets
///      3. Repay debt and return remaining assets to the subaccount
/// @dev The settle call by this order should be performing the necessary swap
/// from collateralVault -> IERC20(borrowVault.asset()). The recipient of the
/// swap should be the account returned by `getInbox(address)`, where `address` is the subaccount. Following this, the account will repay the loan by leveraging an approval from the owner account in `helperRepay`.
/// The order should be of type GPv2Order.KIND_BUY to prevent excess from being sent to the contract.
/// If a full close is being performed, leave a small buffer for intrest accumultation, and the dust will
/// be returned to the owner's wallet.
contract CowEvcClosePositionWrapper is CowEvcBaseWrapper {
    using SafeERC20 for IERC20;

    address immutable VAULT_RELAYER;

    error NoSwapOutput(address inboxForSwap);
    error InsufficientDebt(uint256 expectedMinDebt, uint256 actualDebt);

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
        uint256 leftoverAmount
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
                minRepay: 0,
                kind: bytes32(0)
            })
        )
        .length;

        MAX_BATCH_OPERATIONS = 2;

        PARAMS_TYPE_HASH = keccak256(
            "ClosePositionParams(address owner,address account,uint256 deadline,address borrowVault,address collateralVault,uint256 collateralAmount,uint256 minRepay,bytes32 kind)"
        );

        VAULT_RELAYER = SETTLEMENT.vaultRelayer();
    }

    /// @notice Compute the Inbox address for a given owner and subaccount (view-only, does not deploy)
    /// @param owner The owner address
    /// @param subaccount The subaccount address
    /// @return The computed Inbox address
    function _getInboxAddress(address owner, address subaccount) internal view returns (address) {
        bytes32 salt = bytes32(uint256(uint160(subaccount)));
        bytes memory creationCode = abi.encodePacked(type(Inbox).creationCode, abi.encode(address(this), owner));
        return Create2.computeAddress(salt, keccak256(creationCode));
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

        /// @dev The amount of collateral to use for the repayment. Any unused amount for the CoW swap will be returned to the account. In all cases, this should be the same as `sellAmount` in the CoW order.
        uint256 collateralAmount;

        /// @dev The min amount of debt that should be repaid from the users account after the operation completes. In all cases, this should be the same as `buyAmount` in the CoW order.
        uint256 minRepay;

        /// @dev Hint on whether the CoW order is either keccak256("buy") or keccak256("sell"). In all cases, this should be the same as the `kind` in the CoW order. This will affect how much funds are sent to the owner account
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

        // For the permissioned operation, transfer collateral directly to the Inbox for this user
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: params.account,
            targetContract: params.collateralVault,
            value: 0,
            data: abi.encodeCall(
                IERC20.transfer, (_getInboxAddress(params.owner, params.account), params.collateralAmount)
            )
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

        // Subaccounts in the EVC can be any account that shares the highest 19 bits as the owner.
        // Here we verify that the subaccount address has been specified is, in fact, a subaccount of the owner.
        // Otherwise its concievably possible that a transfer could happen between an owner with an unauthorized subaccount.
        require(
            bytes19(bytes20(params.owner)) == bytes19(bytes20(params.account)),
            SubaccountMustBeControlledByOwner(params.account, params.owner)
        );

        _invokeEvc(
            _makeInternalSettleCallbackData(settleData, wrapperData, remainingWrapperData),
            memoryLocation(params),
            signature,
            params.owner,
            params.deadline
        );
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) internal override {
        (ClosePositionParams memory params,) = _parseClosePositionParams(wrapperData);
        IERC20 borrowAsset = IERC20(IERC4626(params.borrowVault).asset());
        uint256 debtAmount = IBorrowing(params.borrowVault).debtOf(params.account);

        Inbox inbox = _getInbox(params.owner, params.account);
        inbox.callApprove(params.collateralVault, VAULT_RELAYER, type(uint256).max);

        // Use CowWrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _next(settleData, remainingWrapperData);

        // what is the maximum amount of debt that can
        // be repaid from the owner account?
        uint256 swapSourceBalance = IERC20(params.collateralVault).balanceOf(address(inbox));
        uint256 swapResultBalance = borrowAsset.balanceOf(address(inbox));

        if (swapResultBalance == 0) {
            revert NoSwapOutput(address(inbox));
        }

        // send any source collateral that remains after the swap back to the user's account
        if (swapSourceBalance > 0) {
            inbox.callTransfer(params.collateralVault, params.account, swapSourceBalance);
        }

        // the amount we will *actually* repay is the same as however much we get from swapping
        uint256 repayAmount = swapResultBalance;

        // we can't repay more than the available debt amount
        if (repayAmount > debtAmount) {
            // There will be leftover funds in the contract after repaying. Lets send that to the owner's account
            inbox.callTransfer(address(borrowAsset), params.owner, repayAmount - debtAmount);

            repayAmount = debtAmount;
        }

        // repay what was requested on the vault
        inbox.callVaultRepay(params.borrowVault, address(borrowAsset), repayAmount, params.account);

        emit CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            repayAmount,
            swapResultBalance - repayAmount
        );
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
