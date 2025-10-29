// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, CowSettlement} from "./vendor/CowWrapper.sol";
import {IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20Lib} from "euler-vault-kit/src/EVault/shared/lib/SafeERC20Lib.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

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
contract CowEvcClosePositionWrapper is CowWrapper, PreApprovedHashes {
    IEVC public immutable EVC;

    /// @dev The EIP-712 domain type hash used for computing the domain
    /// separator.
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 private constant DOMAIN_NAME = keccak256("CowEvcClosePositionWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 private constant DOMAIN_VERSION = keccak256("1");

    /// @dev The marker value for a sell order for computing the order struct
    /// hash. This allows the EIP-712 compatible wallets to display a
    /// descriptive string for the order kind (instead of 0 or 1).
    ///
    /// This value is pre-computed from the following expression:
    /// ```
    /// keccak256("sell")
    /// ```
    bytes32 private constant KIND_SELL =
        hex"f3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775";

    /// @dev The OrderKind marker value for a buy order for computing the order
    /// struct hash.
    ///
    /// This value is pre-computed from the following expression:
    /// ```
    /// keccak256("buy")
    /// ```
    bytes32 private constant KIND_BUY =
        hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc";

    /// @dev The domain separator used for signing orders that gets mixed in
    /// making signatures for different domains incompatible. This domain
    /// separator is computed following the EIP-712 standard and has replay
    /// protection mixed in so that signed orders are only valid for specific
    /// this contract.
    bytes32 public immutable DOMAIN_SEPARATOR;

    //// @dev The EVC nonce namespace to use when calling `EVC.permit` to authorize this contract.
    uint256 public immutable NONCE_NAMESPACE;

    /// @dev A descriptive label for this contract, as required by CowWrapper
    string public override name = "Euler EVC - Close Position";

    /// @dev Indicates that the current operation cannot be completed with the given msgSender
    error Unauthorized(address msgSender);

    /// @dev Indicates that the pre-approved hash is no longer able to be executed because the block timestamp is too old
    error OperationDeadlineExceeded(uint256 validToTimestamp, uint256 currentTimestamp);

    /// @dev Indicates that this contract did not receive enough repayment assets from the settlement contract in order to cover all user's orders
    error InsufficientRepaymentAsset(address vault, uint256 balanceAmount, uint256 repayAmount);

    /// @dev Indicates that the close order cannot be executed becuase the necessary pricing data is not present in the `tokens`/`clearingPrices` variable
    error PricesNotFoundInSettlement(address collateralVaultToken, address borrowToken);

    /// @dev Indicates that a user attempted to interact with an account that is not their own
    error SubaccountMustBeControlledByOwner(address subaccount, address owner);

    constructor(address _evc, CowSettlement _settlement) CowWrapper(_settlement) {
        EVC = IEVC(_evc);
        NONCE_NAMESPACE = uint256(uint160(address(this)));

        DOMAIN_SEPARATOR =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, DOMAIN_NAME, DOMAIN_VERSION, block.chainid, address(this)));
    }

    /**
     * @notice A command to close a debt position against an euler vault by repaying debt and returning collateral.
     * @dev This structure is used, combined with domain separator, to indicate a pre-approved hash.
     * the `deadline` is used for deduplication checking, so be careful to ensure this value is unique.
     */

    struct ClosePositionParams {
        /**
         * @dev The ethereum address that has permission to operate upon the account
         */
        address owner;

        /**
         * @dev The subaccount to close the position on. Learn more about Euler subaccounts https://evc.wtf/docs/concepts/internals/sub-accounts
         */
        address account;

        /**
         * @dev A date by which this operation must be completed
         */
        uint256 deadline;

        /**
         * @dev The Euler vault from which debt was borrowed
         */
        address borrowVault;

        /**
         * @dev The Euler vault used as collateral
         */
        address collateralVault;

        /**
         * @dev 
         */
        uint256 collateralAmount;

        /**
         * @dev The amount of debt to repay. If greater than the actual debt, the full debt is repaid
         */
        uint256 repayAmount;

        /**
         * @dev Whether the `collateralAmount` or `repayAmount` is the exact amount. Either `GPv2Order.KIND_BUY` or `GPv2Order.KIND_SELL`
         */
        bytes32 kind;
    }

    function _parseClosePositionParams(bytes calldata wrapperData)
        internal
        pure
        returns (ClosePositionParams memory params, bytes memory signature, bytes calldata remainingWrapperData)
    {
        (params, signature) = abi.decode(wrapperData, (ClosePositionParams, bytes));

        // Calculate consumed bytes for abi.encode(ClosePositionParams, bytes)
        // Structure:
        // - 32 bytes: offset to params (0x40)
        // - 32 bytes: offset to signature
        // - 256 bytes: params data (8 fields × 32 bytes)
        // - 32 bytes: signature length
        // - N bytes: signature data (padded to 32-byte boundary)
        // We can just math this out
        uint256 consumed = 256 + 64 + ((signature.length + 31) & ~uint256(31));

        remainingWrapperData = wrapperData[consumed:];
    }

    /// @notice Helper function to compute the hash that would be approved
    /// @param params The ClosePositionParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(ClosePositionParams memory params) external view returns (bytes32) {
        return _getApprovalHash(params);
    }

    function _getApprovalHash(ClosePositionParams memory params) internal view returns (bytes32 digest) {
        bytes32 structHash;
        bytes32 separator = DOMAIN_SEPARATOR;
        assembly ("memory-safe") {
            structHash := keccak256(params, 256)
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), separator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }

    function parseWrapperData(bytes calldata wrapperData)
        external
        pure
        override
        returns (bytes calldata remainingWrapperData)
    {
        (,, remainingWrapperData) = _parseClosePositionParams(wrapperData);
    }

    function getSignedCalldata(ClosePositionParams memory params) external view returns (bytes memory) {
        return abi.encodeCall(IEVC.batch, _getSignedCalldata(params));
    }

    function _getSignedCalldata(ClosePositionParams memory params)
        internal
        view
        returns (IEVC.BatchItem[] memory items)
    {
        items = new IEVC.BatchItem[](1);

        // 1. Repay debt and return remaining assets
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: params.account,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(
                this.helperRepay,
                (params.borrowVault, params.owner, params.account)
            )
        });
    }

    /// @notice Called by the EVC after a CoW swap is completed to repay the user's debt. Will use all available collateral in the user's account to do so.
    /// @param vault The Euler vault in which the repayment should be made
    /// @param owner The address that should be receiving any surplus dust that may exist after the repayment is complete
    /// @param account The subaccount that should be receiving the repayment of debt
    function helperRepay(address vault, address owner, address account)
        external
    {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        (address onBehalfOfAccount,) = EVC.getCurrentOnBehalfOfAccount(address(0));
        require(onBehalfOfAccount == owner, Unauthorized(onBehalfOfAccount));

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

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations to close a position
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing ClosePositionParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Decode wrapper data into ClosePositionParams
        ClosePositionParams memory params;
        bytes memory signature;
        (params, signature,) = _parseClosePositionParams(wrapperData);

        // Check if the signed calldata hash is pre-approved
        IEVC.BatchItem[] memory signedItems = _getSignedCalldata(params);
        bool isPreApproved = signature.length == 0 && _consumePreApprovedHash(params.owner, _getApprovalHash(params));

        // Calculate the number of items needed
        uint256 baseItemCount = 2;
        uint256 itemCount = isPreApproved ? baseItemCount - 1 + signedItems.length : baseItemCount;

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](itemCount);
        uint256 itemIndex = 0;

        // Build the EVC batch items for closing a position
        // 1. Settlement call
        items[itemIndex++] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
        });

        // 2. There are two ways this contract can be executed: either the user approves this contract as
        // an operator and supplies a pre-approved hash for the operation to take, or they submit a permit hash
        // for this specific instance
        if (!isPreApproved) {
            items[itemIndex] = IEVC.BatchItem({
                onBehalfOfAccount: address(0),
                targetContract: address(EVC),
                value: 0,
                data: abi.encodeCall(
                    IEVC.permit,
                    (
                        params.owner,
                        address(this),
                        uint256(NONCE_NAMESPACE),
                        EVC.getNonce(bytes19(bytes20(params.owner)), NONCE_NAMESPACE),
                        params.deadline,
                        0,
                        abi.encodeCall(EVC.batch, signedItems),
                        signature
                    )
                )
            });
        } else {
            require(params.deadline >= block.timestamp, OperationDeadlineExceeded(params.deadline, block.timestamp));
            // copy the operations to execute. we can operate on behalf of the user directly
            uint256 signedItemIndex = 0;
            for (; itemIndex < itemCount; itemIndex++) {
                items[itemIndex] = signedItems[signedItemIndex++];
            }
        }

        // 3. Account status check (automatically done by EVC at end of batch)
        // For more info, see: https://evc.wtf/docs/concepts/internals/account-status-checks
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);
    }

    function _findRatePrices(bytes calldata settleData, address collateralVault, address borrowVault)
        internal
        view
        returns (uint256 collateralVaultPrice, uint256 borrowPrice)
    {
        address borrowAsset = IERC4626(borrowVault).asset();
        (address[] memory tokens, uint256[] memory clearingPrices,,) = abi.decode(
            settleData[4:], (address[], uint256[], CowSettlement.CowTradeData[], CowSettlement.CowInteractionData[][3])
        );
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == collateralVault) {
                collateralVaultPrice = clearingPrices[i];
            } else if (tokens[i] == borrowAsset) {
                borrowPrice = clearingPrices[i];
            }
        }
        require(collateralVaultPrice != 0 && borrowPrice != 0, PricesNotFoundInSettlement(collateralVault, borrowAsset));
    }

    /// @notice Internal settlement function called by EVC
    function evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) external payable {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        (address onBehalfOfAccount,) = EVC.getCurrentOnBehalfOfAccount(address(0));
        require(onBehalfOfAccount == address(this), Unauthorized(onBehalfOfAccount));

        ClosePositionParams memory params;
        (params,,) = _parseClosePositionParams(wrapperData);
        _evcInternalSettle(settleData, remainingWrapperData, params);
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata remainingWrapperData,
        ClosePositionParams memory params
    ) internal {
        // If a subaccount is being used, we need to transfer the required amount of collateral for the trade into the owner's wallet.
        // This is required becuase the settlement contract can only pull funds from the wallet that signed the transaction.
        // Since its not possible for a subaccount to sign a transaction due to the private key not existing and their being no
        // contract deployed to the subaccount address, transferring to the owner's account is the only option.
        // Additionally, we don't transfer this collateral directly to the settlement contract because the settlement contract
        // requires receiving of funds from the user's wallet, and cannot be put in the contract in advance.
        if (params.owner != params.account) {
            require(
                bytes19(bytes20(params.owner)) == bytes19(bytes20(params.account)),
                SubaccountMustBeControlledByOwner(params.account, params.owner)
            );

            uint256 transferAmount = params.collateralAmount;

            if (params.kind == KIND_BUY) {
                (uint256 collateralVaultPrice, uint256 borrowPrice) =
                    _findRatePrices(settleData, params.collateralVault, params.borrowVault);
                transferAmount = params.repayAmount * borrowPrice / collateralVaultPrice;
            }

            SafeERC20Lib.safeTransferFrom(
                IERC20(params.collateralVault), params.account, params.owner, transferAmount, address(0)
            );
        }

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _internalSettle(settleData, remainingWrapperData);
    }
}
