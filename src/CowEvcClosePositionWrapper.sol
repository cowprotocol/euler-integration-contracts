// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
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
    bytes32 private constant KIND_SELL = keccak256("sell");

    /// @dev The OrderKind marker value for a buy order for computing the order
    /// struct hash.
    bytes32 private constant KIND_BUY = keccak256("buy");

    /// @dev Used by EIP-712 signing to prevent signatures from being replayed
    bytes32 public immutable DOMAIN_SEPARATOR;

    //// @dev The EVC nonce namespace to use when calling `EVC.permit` to authorize this contract.
    uint256 public immutable NONCE_NAMESPACE;

    /// @dev A descriptive label for this contract, as required by CowWrapper
    string public override name = "Euler EVC - Close Position";

    uint256 private immutable PARAMS_SIZE;

    /// @dev Indicates that the current operation cannot be completed with the given msgSender
    error Unauthorized(address msgSender);

    /// @dev Indicates that the pre-approved hash is no longer able to be executed because the block timestamp is too old
    error OperationDeadlineExceeded(uint256 validToTimestamp, uint256 currentTimestamp);

    /// @dev Indicates that this contract did not receive enough repayment assets from the settlement contract in order to cover all user's orders
    error InsufficientRepaymentAsset(address vault, uint256 balanceAmount, uint256 repayAmount);

    /// @dev Indicates that a user attempted to interact with an account that is not their own
    error SubaccountMustBeControlledByOwner(address subaccount, address owner);

    /// @dev Indicates that the EVC called `evcInternalSettle` in an invalid way
    error InvalidCallback();

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

    /// @dev Used to ensure that the EVC is calling back this contract with the correct data
    bytes32 internal transient expectedEvcInternalSettleCallHash;

    constructor(address _evc, ICowSettlement _settlement) CowWrapper(_settlement) {
        require(_evc.code.length > 0, "EVC address is invalid");
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
        EVC = IEVC(_evc);
        NONCE_NAMESPACE = uint256(uint160(address(this)));

        DOMAIN_SEPARATOR =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, DOMAIN_NAME, DOMAIN_VERSION, block.chainid, address(this)));
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
        view
        returns (ClosePositionParams memory params, bytes memory signature, bytes calldata remainingWrapperData)
    {
        (params, signature) = abi.decode(wrapperData, (ClosePositionParams, bytes));

        // Calculate consumed bytes for abi.encode(ClosePositionParams, bytes)
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
    /// @param params The ClosePositionParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(ClosePositionParams memory params) external view returns (bytes32) {
        return _getApprovalHash(params);
    }

    function _getApprovalHash(ClosePositionParams memory params) internal view returns (bytes32 digest) {
        bytes32 structHash;
        bytes32 separator = DOMAIN_SEPARATOR;
        uint256 paramsSize = PARAMS_SIZE;
        assembly ("memory-safe") {
            structHash := keccak256(params, paramsSize)
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), separator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }

    function parseWrapperData(bytes calldata wrapperData)
        external
        view
        override
        returns (bytes calldata remainingWrapperData)
    {
        (,, remainingWrapperData) = _parseClosePositionParams(wrapperData);
    }

    function getSignedCalldata(ClosePositionParams memory params) external view returns (bytes memory) {
        return abi.encodeCall(IEVC.batch, _encodeSignedBatchItems(params));
    }

    function _encodeSignedBatchItems(ClosePositionParams memory params)
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
            data: abi.encodeCall(this.helperRepay, (params.borrowVault, params.owner, params.account))
        });
    }

    /// @notice Called by the EVC after a CoW swap is completed to repay the user's debt. Will use all available collateral in the user's account to do so.
    /// @param vault The Euler vault in which the repayment should be made
    /// @param owner The address that should be receiving any surplus dust that may exist after the repayment is complete
    /// @param account The subaccount that should be receiving the repayment of debt
    function helperRepay(address vault, address owner, address account) external {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        (address onBehalfOfAccount,) = EVC.getCurrentOnBehalfOfAccount(address(0));
        require(onBehalfOfAccount == account, Unauthorized(onBehalfOfAccount));

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
        IEVC.BatchItem[] memory signedItems = _encodeSignedBatchItems(params);
        bool isPreApproved = signature.length == 0 && _consumePreApprovedHash(params.owner, _getApprovalHash(params));

        // Calculate the number of items needed
        uint256 baseItemCount = 2;
        uint256 itemCount = isPreApproved ? baseItemCount - 1 + signedItems.length : baseItemCount;

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](itemCount);
        uint256 itemIndex = 0;

        // Build the EVC batch items for closing a position
        // 1. Settlement call
        bytes memory callbackData =
            abi.encodeCall(this.evcInternalSettle, (settleData, wrapperData, remainingWrapperData));
        expectedEvcInternalSettleCallHash = keccak256(callbackData);
        items[itemIndex++] = IEVC.BatchItem({
            onBehalfOfAccount: address(this), targetContract: address(this), value: 0, data: callbackData
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
                        0, // value field (no ETH transferred to the EVC)
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

    /// @notice Internal settlement function called by EVC
    function evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) external payable {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        require(expectedEvcInternalSettleCallHash == keccak256(msg.data), InvalidCallback());
        expectedEvcInternalSettleCallHash = bytes32(0);

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

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
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
}
