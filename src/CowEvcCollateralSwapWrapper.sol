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
        uint256 swapAmount,
        bytes32 kind
    );

    constructor(address _evc, ICowSettlement _settlement)
        CowEvcBaseWrapper(_evc, _settlement, DOMAIN_NAME, DOMAIN_VERSION, 2)
    {
        PARAMS_SIZE =
        abi.encode(
            CollateralSwapParams({
                owner: address(0),
                account: address(0),
                deadline: 0,
                fromVault: address(0),
                toVault: address(0),
                swapAmount: 0,
                kind: bytes32(0)
            })
        )
        .length;
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

        /// @dev The amount of collateral to swap from the source vault
        uint256 swapAmount;

        /// @dev Effectively determines whether this is an exactIn or exactOut order. Must be either KIND_BUY or KIND_SELL as defined in GPv2Order. Should be the same as whats in the actual order.
        bytes32 kind;
    }

    function _parseCollateralSwapParams(bytes calldata wrapperData)
        internal
        view
        returns (CollateralSwapParams memory params, bytes memory signature, bytes calldata remainingWrapperData)
    {
        (params, signature) = abi.decode(wrapperData, (CollateralSwapParams, bytes));

        // Calculate consumed bytes for abi.encode(CollateralSwapParams, bytes)
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
    /// @param params The CollateralSwapParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(CollateralSwapParams memory params) external view returns (bytes32) {
        return _getApprovalHash(memoryLocation(params));
    }

    /// @inheritdoc CowWrapper
    function validateWrapperData(bytes calldata wrapperData) external view override {
        // Validate by attempting to parse the wrapper data
        // Will revert if the data is malformed
        _parseCollateralSwapParams(wrapperData);
    }

    /// @notice Helper function to compute the `data` field needed for the `EVC.permit` call executed by this function
    /// @param params The CollateralSwapParams needed to construct the permit
    /// @return The `data` field of the EVC.permit call which should be signed
    function getSignedCalldata(CollateralSwapParams memory params) external view returns (bytes memory) {
        (IEVC.BatchItem[] memory items,) = _encodeBatchItemsAfter(memoryLocation(params));
        return abi.encodeCall(IEVC.batch, (items));
    }

    function _encodeBatchItemsAfter(ParamsLocation paramsLocation)
        internal
        view
        override
        returns (IEVC.BatchItem[] memory items, bool needsPermit)
    {
        CollateralSwapParams memory params = paramsFromMemory(paramsLocation);
        items = new IEVC.BatchItem[](1);

        // Enable the destination collateral vault for the account
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.enableCollateral, (params.account, params.toVault))
        });

        needsPermit = true;
    }

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations to swap collateral
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing CollateralSwapParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Decode wrapper data into CollateralSwapParams
        CollateralSwapParams memory params;
        bytes memory signature;
        (params, signature,) = _parseCollateralSwapParams(wrapperData);

        _invokeEvc(
            settleData,
            wrapperData,
            remainingWrapperData,
            memoryLocation(params),
            signature,
            params.owner,
            params.deadline
        );

        emit CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) internal override {
        (CollateralSwapParams memory params,,) = _parseCollateralSwapParams(wrapperData);
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

            uint256 transferAmount = params.swapAmount;

            if (params.kind == KIND_BUY) {
                // transfer as much as we can (we will send the remainder back later)
                transferAmount = IERC20(params.fromVault).balanceOf(params.account);
                balanceBefore = IERC20(params.fromVault).balanceOf(params.owner);
            }

            SafeERC20Lib.safeTransferFrom(
                IERC20(params.fromVault), params.account, params.owner, transferAmount, address(0)
            );
        }

        // Use CowWrapper's _next to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _next(settleData, remainingWrapperData);

        if (params.kind == KIND_BUY) {
            // return any remainder to the subaccount
            uint256 balanceAfter = IERC20(params.fromVault).balanceOf(params.owner);

            if (balanceAfter > balanceBefore) {
                SafeERC20Lib.safeTransferFrom(
                    IERC20(params.fromVault), params.owner, params.account, balanceAfter - balanceBefore, address(0)
                );
            }
        }
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
