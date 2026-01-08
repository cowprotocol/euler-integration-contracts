// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20Lib} from "euler-vault-kit/src/EVault/shared/lib/SafeERC20Lib.sol";
import {CowEvcBaseWrapper} from "./CowEvcBaseWrapper.sol";

/// @title CowEvcCollateralSwapWrapper
/// @notice A specialized wrapper for swapping collateral between vaults with EVC
/// @dev This wrapper enables atomic collateral swaps:
///      1. Enable new collateral vault
///      2. Transfer collateral from EVC subaccount to main account (if using subaccount)
///      3. Execute settlement to swap collateral (new collateral is deposited directly into user's account)
///      All operations are atomic within EVC batch
contract CowEvcCollateralSwapWrapper is CowEvcBaseWrapper {
    error InvalidSettlement(address fromVault, address toVault, uint256 fromVaultPrice, uint256 toVaultPrice);

    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 constant DOMAIN_NAME = keccak256("CowEvcCollateralSwapWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 constant DOMAIN_VERSION = keccak256("1");

    /// @dev A descriptive label for this contract, as required by CowWrapper
    string public override name = "Euler EVC - Collateral Swap";

    /// @dev Emitted when collateral is swapped via this wrapper
    event CowEvcCollateralSwapped(
        address indexed owner,
        address account,
        address indexed fromVault,
        address indexed toVault,
        uint256 fromAmount,
        uint256 toAmount,
        bytes32 kind
    );

    constructor(address _evc, ICowSettlement _settlement)
        CowEvcBaseWrapper(_evc, _settlement, DOMAIN_NAME, DOMAIN_VERSION)
    {
        PARAMS_SIZE =
        abi.encode(
            CollateralSwapParams({
                owner: address(0),
                account: address(0),
                deadline: 0,
                fromVault: address(0),
                toVault: address(0),
                fromAmount: 0,
                toAmount: 0,
                kind: bytes32(0)
            })
        )
        .length;

        MAX_BATCH_OPERATIONS = 3;

        PARAMS_TYPE_HASH = keccak256(
            "CollateralSwapParams(address owner,address account,uint256 deadline,address fromVault,address toVault,uint256 swapAmount,bytes32 kind)"
        );
    }

    /// @notice The information necessary to swap collateral between vaults
    /// @dev This structure is used, combined with domain separator, to indicate a pre-approved hash.
    /// the `deadline` is used for deduplication checking, so be careful to ensure this value is unique.
    struct CollateralSwapParams {
        /// @dev The ethereum address that has permission to operate upon the account
        address owner;

        /// @dev The subaccount to swap collateral from. Learn more about Euler subaccounts https://evc.wtf/docs/concepts/internals/sub-accounts
        address account;

        /// @dev A date by which this operation must be completed
        uint256 deadline;

        /// @dev The source collateral vault (what we're swapping from)
        address fromVault;

        /// @dev The destination collateral vault (what we're swapping to)
        address toVault;

        /// @dev The amount of fromVault traded in. Same as `sellAmount` in the CoW order
        uint256 fromAmount;

        /// @dev The amount of toVault traded out. Same as `buyAmount` in the CoW order
        uint256 toAmount;

        /// @dev Effectively determines whether this is an exactIn or exactOut order. Must be either KIND_BUY or KIND_SELL as defined in GPv2Order. Should be the same as whats in the actual order.
        bytes32 kind;
    }

    function _parseCollateralSwapParams(bytes calldata wrapperData)
        internal
        pure
        returns (CollateralSwapParams memory params, bytes memory signature)
    {
        (params, signature) = abi.decode(wrapperData, (CollateralSwapParams, bytes));
    }

    /// @notice Helper function to compute the hash that would be approved
    /// @param params The CollateralSwapParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(CollateralSwapParams memory params) external view returns (bytes32) {
        return _getApprovalHash(memoryLocation(params));
    }

    /// @inheritdoc CowWrapper
    function validateWrapperData(bytes calldata wrapperData) external pure override {
        // Validate by attempting to parse the wrapper data
        // Will revert if the data is malformed
        _parseCollateralSwapParams(wrapperData);
    }

    /// @notice Called by an offchain process to determine what data should be signed in a call to `wrappedSettle`.
    /// @param params The parameters object provided as input to the wrapper
    /// @return The `EVC` call that would be submitted to `EVC.permit`. This would need to be signed as documented https://evc.wtf/docs/concepts/internals/permit.
    function encodePermitData(CollateralSwapParams memory params) external view returns (bytes memory) {
        (IEVC.BatchItem[] memory items,) = _encodeBatchItemsBefore(memoryLocation(params));
        return _encodePermitData(items, memoryLocation(params));
    }

    function _encodeBatchItemsBefore(ParamsLocation paramsLocation)
        internal
        view
        override
        returns (IEVC.BatchItem[] memory items, bool needsPermission)
    {
        CollateralSwapParams memory params = paramsFromMemory(paramsLocation);
        items = new IEVC.BatchItem[](MAX_BATCH_OPERATIONS - 1);

        // For the permissioned operation, transfer collateral from subaccount to owner
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(params.account),
            targetContract: params.fromVault,
            value: 0,
            data: abi.encodeCall(IERC20.transfer, (address(this), params.fromAmount))
        });
        // also, enable the new account for collateral
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(EVC.enableCollateral, (params.account, params.toVault))
        });

        needsPermission = true;
    }

    /// @notice Implementation of CowWrapper._wrap - executes EVC operations to swap collateral
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing CollateralSwapParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Decode wrapper data into CollateralSwapParams
        (CollateralSwapParams memory params, bytes memory signature) = _parseCollateralSwapParams(wrapperData);

        // Subaccounts in the EVC can be any account that shares the highest 19 bits as the owner.
        // Here we verify that the subaccount address is, in fact, a subaccount of the owner.
        // Otherwise it's conceivably possible that a transfer could happen between an owner with an unauthorized subaccount.
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
        (CollateralSwapParams memory params,) = _parseCollateralSwapParams(wrapperData);
        (address[] memory tokens, uint256[] memory prices,,) =
            abi.decode(settleData[4:], (address[], uint256[], ICowSettlement.Trade[], ICowSettlement.Interaction[][3]));

        uint256 fromVaultTokenPrice;
        uint256 toVaultTokenPrice;
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == address(params.fromVault)) {
                fromVaultTokenPrice = prices[i];
            } else if (tokens[i] == address(params.toVault)) {
                toVaultTokenPrice = prices[i];
            }
        }

        require(
            fromVaultTokenPrice > 0 && toVaultTokenPrice > 0,
            InvalidSettlement(params.fromVault, params.toVault, fromVaultTokenPrice, toVaultTokenPrice)
        );

        // For KIND_BUY orders, we need to calculate how much collateral is actually needed and send back the remainder
        uint256 fromAmount;
        uint256 toAmount;
        if (params.kind == KIND_BUY) {
            // Calculate and send only what's needed for the swap, send remainder back to account
            fromAmount = params.toAmount * toVaultTokenPrice / fromVaultTokenPrice;
            toAmount = params.toAmount;
            SafeERC20Lib.safeTransfer(IERC20(params.fromVault), params.owner, fromAmount);

            uint256 remainingBalance = IERC20(params.fromVault).balanceOf(address(this));
            if (remainingBalance > 0) {
                SafeERC20Lib.safeTransfer(IERC20(params.fromVault), params.account, remainingBalance);
            }
        } else {
            fromAmount = params.fromAmount;
            toAmount = params.fromAmount * fromVaultTokenPrice / toVaultTokenPrice;
            // For KIND_SELL: send all collateral to owner and let settlement send remainder back
            SafeERC20Lib.safeTransfer(
                IERC20(params.fromVault), params.owner, IERC20(params.fromVault).balanceOf(address(this))
            );
        }

        // Use CowWrapper's _next to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _next(settleData, remainingWrapperData);

        // Emit event - funds are now in the account from the settlement
        emit CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, fromAmount, toAmount, params.kind
        );
    }

    function memoryLocation(CollateralSwapParams memory params) internal pure returns (ParamsLocation location) {
        assembly ("memory-safe") {
            location := params
        }
    }

    function paramsFromMemory(ParamsLocation location) internal pure returns (CollateralSwapParams memory params) {
        assembly {
            params := location
        }
    }
}
