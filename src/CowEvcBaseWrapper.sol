// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

import {Inbox} from "./Inbox.sol";

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

    /// @dev The EIP-712 type hash of the parameters structure used by this wrapper.
    bytes32 public immutable PARAMS_TYPE_HASH;

    /// @dev How long to make the `items` array without calculating it. Determines the maximum number of EVC operations that can be batched.
    /// This value depends on the each concrete wrapper implementation. It should include the settlement and any operations before and after it.
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

    /// @dev Indicates that the constructed EVC operations are exceeding the maximum length allowed. Generally this is a sanity check
    error ItemsOutOfBounds(uint256 itemIndex, uint256 maxItemIndex);

    /// @dev Used to ensure that the EVC is calling back this contract with the correct data
    bytes32 internal transient expectedEvcInternalSettleCallHash;

    constructor(address _evc, ICowSettlement _settlement, bytes32 _domainName, bytes32 _domainVersion)
        CowWrapper(_settlement)
    {
        require(_evc.code.length > 0, "EVC address is invalid");
        EVC = IEVC(_evc);
        NONCE_NAMESPACE = uint256(uint160(address(this)));
        DOMAIN_SEPARATOR =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, _domainName, _domainVersion, block.chainid, address(this)));
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
    /// @param params The memory location of the struct data
    /// @return digest The EIP-712 compliant digest
    function _getApprovalHash(ParamsLocation params) internal view returns (bytes32 digest) {
        bytes32 structHash;
        bytes32 separator = DOMAIN_SEPARATOR;
        bytes32 typeHash = PARAMS_TYPE_HASH;
        uint256 paramsSize = PARAMS_SIZE;
        assembly {
            // Build structHash = keccak256(typeHash || encodeData(params))
            let wordBeforeParamPtr := sub(params, 0x20)
            // Subtraction overflow causes the next line to revert with out of gas if params isn't allocated
            let wordBeforeParam := mload(wordBeforeParamPtr)
            mstore(wordBeforeParamPtr, typeHash)
            structHash := keccak256(wordBeforeParamPtr, add(0x20, paramsSize))
            // Restore original content
            mstore(wordBeforeParamPtr, wordBeforeParam)

            // Build digest = keccak256("\x19\x01" || domainSeparator || structHash)
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), separator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }

    /// @notice Generates the permit data that would be used for the given EVC batch items (presumably generated from params)
    function _encodePermitData(IEVC.BatchItem[] memory items, ParamsLocation params)
        internal
        view
        returns (bytes memory)
    {
        // The abi.encodeCall() part consists of the batch call that we want to execute. The additional data tacked on the end is to ensure
        // the provided parameters are all validated against the user signature, even if `items` doesn't completely use the parameters in effect.
        return abi.encodePacked(abi.encodeCall(IEVC.batch, items), _getApprovalHash(params));
    }

    /// @notice This function is called by EVC and continues the CoW settlement process inside an EVC batch while including any necessary security check.
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

    /// @notice This function is called by an offchain process as part of constructing the CoW order needed to use this wrapper.
    /// @dev Read the wrapper documentation to confirm. It may or may not be necessary to set the `recipient` of the CoW order to the address returned
    /// by this function.
    function getInbox(address owner, address subaccount) external returns (address) {
        return _getInbox(owner, subaccount);
    }

    function _getInbox(address owner, address subaccount) internal returns (address) {
        bytes32 salt = bytes32(uint256(uint160(subaccount)));
        address expectedAddress = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            salt,
                            keccak256(abi.encodePacked(type(Inbox).creationCode, abi.encode(address(this), owner)))
                        )
                    )
                )
            )
        );

        if (expectedAddress.code.length == 0) {
            new Inbox{salt: salt}(address(this), owner);
        }

        return expectedAddress;
    }

    function _callInbox(address inbox, address target, bytes memory data) internal {
        (bool success, bytes memory reason) = inbox.call(abi.encodePacked(target, data));
        if (!success) {
            assembly ("memory-safe") {
                revert(add(0x20, reason), mload(reason))
            }
        }
    }

    function _invokeEvc(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData,
        ParamsLocation param,
        bytes memory signature,
        address owner,
        uint256 deadline
    ) internal {
        // There are 2 ways that this contract can validate user operations: 1) the user pre-approves a hash with an on-chain call and grants this contract ability to operate on the user's behalf, or 2) they issue a signature which can be used to call EVC.permit()
        // In case the user is using a hash (1), then there would be no signature supplied to this call and we have to resolve the hash instead
        // If its flow (2), it happens through the call to EVC.permit() elsewhere: if the parameters don't match with the user intent, that call is assumed to revert.
        // In this case, we need to check that `permit` has been called by the actual wrapper implementation.
        if (signature.length == 0) {
            _consumePreApprovedHash(owner, _getApprovalHash(param));
            // The deadline is checked by `EVC.permit()`, so we only check it here if we are using a pre-approved hash (aka, no signature) which would bypass that call
            require(deadline >= block.timestamp, OperationDeadlineExceeded(deadline, block.timestamp));
        }

        // Build the EVC batch items for swapping collateral
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](MAX_BATCH_OPERATIONS);

        uint256 itemIndex = 0;

        // add any EVC actions that have to be performed before
        {
            (IEVC.BatchItem[] memory beforeItems, bool needsPermission) = _encodeBatchItemsBefore(param);
            itemIndex = _addEvcBatchItems(
                items,
                beforeItems,
                itemIndex,
                owner,
                deadline,
                signature,
                needsPermission ? param : ParamsLocation.wrap(bytes32(0))
            );
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
            (IEVC.BatchItem[] memory afterItems, bool needsPermission) = _encodeBatchItemsAfter(param);
            itemIndex = _addEvcBatchItems(
                items,
                afterItems,
                itemIndex,
                owner,
                deadline,
                signature,
                needsPermission ? param : ParamsLocation.wrap(bytes32(0))
            );
        }

        // shorten the length of the generated array to its actual length
        require(itemIndex <= MAX_BATCH_OPERATIONS, ItemsOutOfBounds(itemIndex, MAX_BATCH_OPERATIONS));
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
        ParamsLocation param
    ) internal view returns (uint256) {
        // There are two ways this contract can be executed: either the user approves this contract as
        // an operator and supplies a pre-approved hash for the operation to take, or they submit a permit hash
        // for this specific instance. If its the permit hash route, here we call `permit` instead of `batch` raw so that the EVC can authorize it.
        // If there is an issue with the signature, the EVC will revert the batch call, which will bubble up through this contract to revert the entire wrappedSettle call.
        if (ParamsLocation.unwrap(param) != bytes32(0) && signature.length > 0) {
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
                        _encodePermitData(addItems, param),
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
