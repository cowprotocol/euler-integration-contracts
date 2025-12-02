// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

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
contract CowEvcOpenPositionWrapper is CowWrapper, PreApprovedHashes {
    IEVC public immutable EVC;

    /// @dev The EIP-712 domain type hash used for computing the domain
    /// separator.
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 private constant DOMAIN_NAME = keccak256("CowEvcOpenPositionWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 private constant DOMAIN_VERSION = keccak256("1");

    /// @dev Used by EIP-712 signing to prevent signatures from being replayed
    bytes32 public immutable DOMAIN_SEPARATOR;

    //// @dev The EVC nonce namespace to use when calling `EVC.permit` to authorize this contract.
    uint256 public immutable NONCE_NAMESPACE;

    /// @dev A descriptive label for this contract, as required by CowWrapper
    string public override name = "Euler EVC - Open Position";

    uint256 private immutable PARAMS_SIZE;

    /// @dev Indicates that the current operation cannot be completed with the given msgSender
    error Unauthorized(address msgSender);

    /// @dev Indicates that the pre-approved hash is no longer able to be executed because the block timestamp is too old
    error OperationDeadlineExceeded(uint256 validToTimestamp, uint256 currentTimestamp);

    /// @dev Emitted when a position is opened via this wrapper
    event CowEvcPositionOpened(
        address indexed owner,
        address account,
        address indexed collateralVault,
        address indexed borrowVault,
        uint256 collateralAmount,
        uint256 borrowAmount
    );

    constructor(address _evc, ICowSettlement _settlement) CowWrapper(_settlement) {
        require(_evc.code.length > 0, "EVC address is invalid");
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
        EVC = IEVC(_evc);
        NONCE_NAMESPACE = uint256(uint160(address(this)));

        DOMAIN_SEPARATOR =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, DOMAIN_NAME, DOMAIN_VERSION, block.chainid, address(this)));
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
        return _getApprovalHash(params);
    }

    function _getApprovalHash(OpenPositionParams memory params) internal view returns (bytes32 digest) {
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
        (,, remainingWrapperData) = _parseOpenPositionParams(wrapperData);
    }

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations to open a position
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing OpenPositionParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Decode wrapper data into OpenPositionParams
        OpenPositionParams memory params;
        bytes memory signature;
        (params, signature,) = _parseOpenPositionParams(wrapperData);

        // Check if the signed calldata hash is pre-approved
        IEVC.BatchItem[] memory signedItems = _encodeSignedBatchItems(params);
        bool isPreApproved = signature.length == 0 && _consumePreApprovedHash(params.owner, _getApprovalHash(params));

        // Build the EVC batch items for opening a position
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](isPreApproved ? signedItems.length + 1 : 2);

        uint256 itemIndex = 0;

        // 1. There are two ways this contract can be executed: either the user approves this contract as
        // and operator and supplies a pre-approved hash for the operation to take, or they submit a permit hash
        // for this specific instance
        if (!isPreApproved) {
            items[itemIndex++] = IEVC.BatchItem({
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
            for (; itemIndex < signedItems.length; itemIndex++) {
                items[itemIndex] = signedItems[itemIndex];
            }
        }

        // 2. Settlement call
        items[itemIndex] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (settleData, remainingWrapperData))
        });

        // 3. Account status check (automatically done by EVC at end of batch)
        // For more info, see: https://evc.wtf/docs/concepts/internals/account-status-checks
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);

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
        return abi.encodeCall(IEVC.batch, _encodeSignedBatchItems(params));
    }

    function _encodeSignedBatchItems(OpenPositionParams memory params)
        internal
        view
        returns (IEVC.BatchItem[] memory items)
    {
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
    }

    /// @notice Internal settlement function called by EVC
    function evcInternalSettle(bytes calldata settleData, bytes calldata remainingWrapperData) external payable {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        (address onBehalfOfAccount,) = EVC.getCurrentOnBehalfOfAccount(address(0));
        require(onBehalfOfAccount == address(this), Unauthorized(onBehalfOfAccount));

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _next(settleData, remainingWrapperData);
    }
}
