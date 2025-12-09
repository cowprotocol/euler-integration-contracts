// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

/// @title CowEvcBaseWrapper
/// @notice Shared components for implementing Euler wrappers.
abstract contract CowEvcBaseWrapper is CowWrapper, PreApprovedHashes {
    /// @dev location in memory of the parameters describing the wrapper implementation.
    type ParamsLocation is bytes32;

    IEVC public immutable EVC;

    /// @dev The EIP-712 domain type hash used for computing the domain
    /// separator.
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The marker value for a sell order for computing the order struct
    /// hash. This allows the EIP-712 compatible wallets to display a
    /// descriptive string for the order kind (instead of 0 or 1).
    bytes32 internal constant KIND_SELL = keccak256("sell");

    /// @dev The OrderKind marker value for a buy order for computing the order
    /// struct hash.
    bytes32 internal constant KIND_BUY = keccak256("buy");

    /// @dev Used by EIP-712 signing to prevent signatures from being replayed
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @dev The EVC nonce namespace to use when calling `EVC.permit` to authorize this contract.
    /// See: https://evc.wtf/docs/concepts/internals/permit/#nonce-namespaces
    uint256 public immutable NONCE_NAMESPACE;

    /// @dev The length of the parameters consumed by this wrapper. Used in order to know how much data to read after the ParamsLocation for the hash.
    /// Ideally this should be computed by creating the parameters struct and then `abi.encode().length` to ensure its always the correct size.
    uint256 internal immutable PARAMS_SIZE;

    /// @dev How long to make the `items` array without calculating it. Determines the maximum number of EVC operations that can be batched.
    uint256 internal immutable MAX_BATCH_OPERATIONS;

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

    /// @dev Used to ensure that the EVC is calling back this contract with the correct data
    bytes32 internal transient expectedEvcInternalSettleCallHash;

    /**
     * @param _evc The address of the Ethereum Vault Connector on this network
     * @param _settlement The address of the CoW settlement contract
     * @param _domainName The name of this contract that should be used for EIP-712 purposes
     * @param _domainVersion The version of this contract that should be used for EIP-712 purposes
     * @param maxBatchOperations How long to make the array for the executed EVC batch operations in _invokeEvc. This value only needs to be at least as large as the maximum possible length of the EVC batch operations. A way to calculate this is (_encodeBatchItemsBefore.length) + 1 + (_encodeBatchItemsAfter().length) (any excess will be automatically trimmed).
     */
    constructor(
        address _evc,
        ICowSettlement _settlement,
        bytes32 _domainName,
        bytes32 _domainVersion,
        uint256 maxBatchOperations
    ) CowWrapper(_settlement) {
        require(_evc.code.length > 0, "EVC address is invalid");
        EVC = IEVC(_evc);
        NONCE_NAMESPACE = uint256(uint160(address(this)));
        DOMAIN_SEPARATOR =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, _domainName, _domainVersion, block.chainid, address(this)));
        MAX_BATCH_OPERATIONS = maxBatchOperations;
    }

    /// @notice Encode batch items to execute before the settlement
    /// @dev By default we return the default value (empty array, false)
    /// @param location The memory storage position where the parameters needed to encode the batch items have been saved
    /// @return items Array of batch items to execute
    /// @return needsPermit Whether these items require user signature or prior authorization as an operator
    function _encodeBatchItemsBefore(ParamsLocation location)
        internal
        view
        virtual
        returns (IEVC.BatchItem[] memory items, bool needsPermit)
    {}

    /// @notice Encode batch items to execute after the settlement
    /// @dev By default we return the default value (empty array, false)
    /// @param location The memory storage position where the parameters needed to encode the batch items have been saved
    /// @return items Array of batch items to execute
    /// @return needsPermit Whether these items require user signature or prior authorization as an operator
    function _encodeBatchItemsAfter(ParamsLocation location)
        internal
        view
        virtual
        returns (IEVC.BatchItem[] memory items, bool needsPermit)
    {}

    /// @dev This function makes strong assumptions on the memory layout of the struct in memory.
    /// It assumes:
    ///  - The struct itself doesn't contain any dynamic-length types.
    ///  - The struct is encoded in memory with zero padding.
    function _getApprovalHash(ParamsLocation paramsMemoryLocation) internal view returns (bytes32 digest) {
        bytes32 structHash;
        bytes32 separator = DOMAIN_SEPARATOR;
        uint256 paramsSize = PARAMS_SIZE;
        assembly ("memory-safe") {
            structHash := keccak256(paramsMemoryLocation, paramsSize)
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), separator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
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
        _evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function _invokeEvc(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData,
        ParamsLocation paramMemoryLocation,
        bytes memory signature,
        address owner,
        uint256 deadline
    ) internal {
        if (signature.length == 0) {
            _consumePreApprovedHash(owner, _getApprovalHash(paramMemoryLocation));
            // The deadline is checked by `EVC.permit()`, so we only check it here if we are using a pre-approved hash (aka, no signature) which would bypass that call
            require(deadline >= block.timestamp, OperationDeadlineExceeded(deadline, block.timestamp));
        }

        // Build the EVC batch items for swapping collateral
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](MAX_BATCH_OPERATIONS);

        uint256 itemIndex = 0;

        // add any EVC actions that have to be performed before
        {
            (IEVC.BatchItem[] memory beforeItems, bool needsPermission) = _encodeBatchItemsBefore(paramMemoryLocation);
            itemIndex = _addEvcBatchItems(items, beforeItems, itemIndex, owner, deadline, signature, needsPermission);
        }

        // add the EVC callback to this (which calls settlement)
        {
            bytes memory callbackData =
                abi.encodeCall(CowEvcBaseWrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData));
            expectedEvcInternalSettleCallHash = keccak256(callbackData);
            items[itemIndex++] = IEVC.BatchItem({
                onBehalfOfAccount: address(this), targetContract: address(this), value: 0, data: callbackData
            });
        }

        // add the EVC actions that have to be performed after
        {
            (IEVC.BatchItem[] memory afterItems, bool needsPermission) = _encodeBatchItemsAfter(paramMemoryLocation);
            itemIndex = _addEvcBatchItems(items, afterItems, itemIndex, owner, deadline, signature, needsPermission);
        }

        // shorten the length of the generated array to its actual length
        assembly ("memory-safe") {
            mstore(items, itemIndex)
        }

        // 3. Account status check (automatically done by EVC at end of batch)
        // For more info, see: https://evc.wtf/docs/concepts/internals/account-status-checks
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);
    }

    function _addEvcBatchItems(
        IEVC.BatchItem[] memory fullItems,
        IEVC.BatchItem[] memory addItems,
        uint256 itemIndex,
        address owner,
        uint256 deadline,
        bytes memory signature,
        bool needsPermission
    ) internal view returns (uint256) {
        // There are two ways this contract can be executed: either the user approves this contract as
        // an operator and supplies a pre-approved hash for the operation to take, or they submit a permit hash
        // for this specific instance
        if (needsPermission && signature.length > 0) {
            fullItems[itemIndex++] = IEVC.BatchItem({
                onBehalfOfAccount: address(0),
                targetContract: address(EVC),
                value: 0,
                data: abi.encodeCall(
                    IEVC.permit,
                    (
                        owner,
                        address(this),
                        uint256(NONCE_NAMESPACE),
                        EVC.getNonce(bytes19(bytes20(owner)), NONCE_NAMESPACE),
                        deadline,
                        0, // value field (no ETH transferred to the EVC)
                        abi.encodeCall(EVC.batch, addItems),
                        signature
                    )
                )
            });
        } else {
            // copy the operations to execute. this contract can operate on behalf of the user directly
            for (uint256 i; i < addItems.length; i++) {
                fullItems[itemIndex + i] = addItems[i];
            }

            itemIndex += addItems.length;
        }

        return itemIndex;
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) internal virtual;
}
