// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20Lib} from "euler-vault-kit/src/EVault/shared/lib/SafeERC20Lib.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

/// @title CowEvcCollateralSwapWrapper
/// @notice A specialized wrapper for swapping collateral between vaults with EVC
/// @dev This wrapper enables atomic collateral swaps:
///      1. Enable new collateral vault
///      2. Transfer collateral from EVC subaccount to main account (if using subaccount)
///      3. Execute settlement to swap collateral (new collateral is deposited directly into user's account)
///      All operations are atomic within EVC batch
contract CowEvcCollateralSwapWrapper is CowWrapper, PreApprovedHashes {
    IEVC public immutable EVC;

    /// @dev The EIP-712 domain type hash used for computing the domain
    /// separator.
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 private constant DOMAIN_NAME = keccak256("CowEvcCollateralSwapWrapper");

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
    string public override name = "Euler EVC - Collateral Swap";

    /// @dev The size of the CollateralSwapParams struct. Its computed in the constructor so it can be used as a constant later.
    uint256 private immutable PARAMS_SIZE;

    /// @dev Indicates that the current operation cannot be completed with the given msgSender
    error Unauthorized(address msgSender);

    /// @dev Indicates that the pre-approved hash is no longer able to be executed because the block timestamp is too old
    error OperationDeadlineExceeded(uint256 validToTimestamp, uint256 currentTimestamp);

    /// @dev Indicates that the collateral swap cannot be executed because the necessary pricing data is not present in the `tokens`/`clearingPrices` variable
    error PricesNotFoundInSettlement(address fromVault, address toVault);

    /// @dev Indicates that a user attempted to interact with an account that is not their own
    error SubaccountMustBeControlledByOwner(address subaccount, address owner);

    /// @dev Emitted when collateral is swapped via this wrapper
    event CowEvcCollateralSwapped(
        address indexed owner,
        address account,
        address indexed fromVault,
        address indexed toVault,
        uint256 swapAmount,
        bytes32 kind
    );

    constructor(address _evc, ICowSettlement _settlement) CowWrapper(_settlement) {
        require(_evc.code.length > 0, "EVC address is invalid");
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
        EVC = IEVC(_evc);
        NONCE_NAMESPACE = uint256(uint160(address(this)));

        DOMAIN_SEPARATOR =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, DOMAIN_NAME, DOMAIN_VERSION, block.chainid, address(this)));
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
        return _getApprovalHash(params);
    }

    function _getApprovalHash(CollateralSwapParams memory params) internal view returns (bytes32 digest) {
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

    /// @inheritdoc CowWrapper
    function parseWrapperData(bytes calldata wrapperData)
        external
        view
        override
        returns (bytes calldata remainingWrapperData)
    {
        (,, remainingWrapperData) = _parseCollateralSwapParams(wrapperData);
    }

    /// @notice Helper function to compute the `data` field needed for the `EVC.permit` call executed by this function
    /// @param params The CollateralSwapParams needed to construct the permit
    /// @return The `data` field of the EVC.permit call which should be signed
    function getSignedCalldata(CollateralSwapParams memory params) external view returns (bytes memory) {
        return abi.encodeCall(IEVC.batch, _encodeSignedBatchItems(params));
    }

    function _encodeSignedBatchItems(CollateralSwapParams memory params)
        internal
        view
        returns (IEVC.BatchItem[] memory items)
    {
        items = new IEVC.BatchItem[](1);

        // Enable the destination collateral vault for the account
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.enableCollateral, (params.account, params.toVault))
        });
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

        // Check if the signed calldata hash is pre-approved
        IEVC.BatchItem[] memory signedItems = _encodeSignedBatchItems(params);
        bool isPreApproved = signature.length == 0 && _consumePreApprovedHash(params.owner, _getApprovalHash(params));

        // Build the EVC batch items for swapping collateral
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](isPreApproved ? signedItems.length + 1 : 2);

        uint256 itemIndex = 0;

        // 1. There are two ways this contract can be executed: either the user approves this contract as
        // an operator and supplies a pre-approved hash for the operation to take, or they submit a permit hash
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
            data: abi.encodeCall(this.evcInternalSwap, (settleData, wrapperData, remainingWrapperData))
        });

        // 3. Account status check (automatically done by EVC at end of batch)
        // For more info, see: https://evc.wtf/docs/concepts/internals/account-status-checks
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);

        emit CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );
    }

    /// @notice Internal swap function called by EVC
    function evcInternalSwap(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) external payable {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        (address onBehalfOfAccount,) = EVC.getCurrentOnBehalfOfAccount(address(0));
        require(onBehalfOfAccount == address(this), Unauthorized(onBehalfOfAccount));

        CollateralSwapParams memory params;
        (params,,) = _parseCollateralSwapParams(wrapperData);
        _evcInternalSwap(settleData, remainingWrapperData, params);
    }

    function _evcInternalSwap(
        bytes calldata settleData,
        bytes calldata remainingWrapperData,
        CollateralSwapParams memory params
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
}
