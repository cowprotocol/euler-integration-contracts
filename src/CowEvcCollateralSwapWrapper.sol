// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {CowEvcBaseWrapper} from "./CowEvcBaseWrapper.sol";

/// @title CowEvcCollateralSwapWrapper
/// @notice A specialized wrapper for swapping collateral between vaults with EVC
/// @dev This wrapper enables atomic collateral swaps by:
///      1. Enabling new collateral vault
///      2. Transfering collateral from EVC subaccount to main account (if using subaccount)
///      3. Executing the settlement contract to swap collateral (new collateral is deposited directly into user's account)
/// @dev When using the pre-approved hash flow (empty signature), this function will
/// revoke operator access for both `owner` and `account` after execution completes.
/// Integrations relying on persistent operator authorization MUST re-grant access
/// before the next operation.
contract CowEvcCollateralSwapWrapper is CowEvcBaseWrapper {
    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 constant DOMAIN_NAME = keccak256("CowEvcCollateralSwapWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 constant DOMAIN_VERSION = keccak256("1");

    /// @dev A descriptive label for this contract, as required by CowWrapper
    string public override name = "Euler EVC - Collateral Swap";

    /// @dev Emitted when collateral is swapped via this wrapper. Note that *all* these values are simply the CollateralSwapParams values, and no the actual trade amounts.
    /// For actual trade amounts, see the `Trade` event emitted by the settlement contract in the same transaction.
    /// @param owner The owner specified in the CollateralSwapParams
    /// @param account The subaccount specified in the CollateralSwapParams
    /// @param fromVault The vault from which collateral is being swapped
    /// @param toVault The vault to which collateral is being swapped
    /// @param fromAmount The amount of collateral being swapped from the fromVault as specified in the CollateralSwapParams. This may differ from the actual swapped amount.
    /// @param disableSourceCollateral The flag from the CollateralSwapParams indicating whether the source collateral was disabled after the swap
    event CowEvcCollateralSwapped(
        address indexed owner,
        address account,
        address indexed fromVault,
        address indexed toVault,
        uint256 fromAmount,
        bool disableSourceCollateral
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
                disableSourceCollateral: false
            })
        )
        .length;

        MAX_BATCH_OPERATIONS = 4;

        PARAMS_TYPE_HASH = keccak256(
            "CollateralSwapParams(address owner,address account,uint256 deadline,address fromVault,address toVault,uint256 fromAmount,bool disableSourceCollateral)"
        );
    }

    /// @notice The information necessary to swap collateral between vaults
    /// @dev This structure is used, combined with domain separator, to indicate a pre-approved hash.
    /// NOTE: If you need to create an order with identical properties to another, ensure that the hash of this structure is unique for this user.
    /// when in doubt, the `deadline` can be incremented to create a new unique order params object
    struct CollateralSwapParams {
        /// @dev The ethereum address that has permission to operate upon the account. In the case that the funds are in a subaccount (i.e. account != owner), collateral will
        /// be atomically transferred into this address prior to the CoW settlement.
        /// The CoW order should be signed or pre-approved from this address.
        address owner;

        /// @dev The subaccount from which the old collateral originates, and where the new collateral will be sent. Learn more about Euler subaccounts https://evc.wtf/docs/concepts/internals/sub-accounts
        /// The CoW order `receiver` should be set to this value.
        address account;

        /// @dev A date by which this operation must be completed
        uint256 deadline;

        /// @dev The source collateral vault (what we're swapping from). Same as `sellToken` in the CoW order
        address fromVault;

        /// @dev The destination collateral vault (what we're swapping to). Same as `buyToken` in the CoW order
        address toVault;

        /// @dev The amount of fromVault traded in. Same as `sellAmount` in the CoW order
        uint256 fromAmount;

        /// @dev A flag to indicate whether the old collateral should be disabled after the swap. If true, the wrapper will additionally call `disableCollateral` on the source vault after the swap.
        bool disableSourceCollateral;
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

    /// @inheritdoc CowEvcBaseWrapper
    function _encodeBatchItemsBefore(ParamsLocation paramsLocation)
        internal
        view
        override
        returns (IEVC.BatchItem[] memory items, bool needsPermission)
    {
        CollateralSwapParams memory params = paramsFromMemory(paramsLocation);

        uint256 numItems = 1;
        if (params.owner != params.account) {
            numItems += 1;
        }
        if (params.disableSourceCollateral) {
            numItems += 1;
        }

        items = new IEVC.BatchItem[](numItems);

        // fill in the items from back to front because its easier working with `numItems`
        // Though the order of none of these calls is important

        // enable the new collateral for account
        items[--numItems] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(EVC.enableCollateral, (params.account, params.toVault))
        });

        if (params.disableSourceCollateral) {
            // If requested, disable the old collateral
            // Note that this can be done before the swap actually occurs because the collateralization check is deferred.
            items[--numItems] = IEVC.BatchItem({
                onBehalfOfAccount: address(0),
                targetContract: address(EVC),
                value: 0,
                data: abi.encodeCall(EVC.disableCollateral, (params.account, params.fromVault))
            });
        }

        if (params.owner != params.account) {
            // For the permissioned operation, transfer collateral from subaccount to owner
            // (this transfer should be safe for general use because its operating against Euler vault contracts)
            items[--numItems] = IEVC.BatchItem({
                onBehalfOfAccount: address(params.account),
                targetContract: params.fromVault,
                value: 0,
                data: abi.encodeCall(IERC20.transfer, (params.owner, params.fromAmount))
            });
        }

        needsPermission = true;
    }

    /// @inheritdoc CowWrapper
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Decode wrapper data into CollateralSwapParams
        (CollateralSwapParams memory params, bytes memory signature) = _parseCollateralSwapParams(wrapperData);

        _invokeEvc(
            _makeInternalSettleCallbackData(settleData, wrapperData, remainingWrapperData),
            memoryLocation(params),
            signature,
            params.owner,
            params.account,
            params.deadline
        );

        // Emit event - funds are now in the account from the settlement
        emit CowEvcCollateralSwapped(
            params.owner,
            params.account,
            params.fromVault,
            params.toVault,
            params.fromAmount,
            params.disableSourceCollateral
        );
    }

    /// @inheritdoc CowEvcBaseWrapper
    function _evcInternalSettle(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Use CowWrapper's _next to proceed with the wrapper chain/settlement
        _next(settleData, remainingWrapperData);
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
