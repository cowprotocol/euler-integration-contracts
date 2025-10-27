// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, CowSettlement} from "./vendor/CowWrapper.sol";
import {IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {SafeERC20Lib} from "euler-vault-kit/src/EVault/shared/lib/SafeERC20Lib.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

/// @title CowEvcCollateralSwapWrapper
/// @notice A specialized wrapper for swapping collateral between vaults with EVC
/// @dev This wrapper enables atomic collateral swaps:
///      1. Transfer collateral from EVC subaccount to main account (if using subaccount)
///      2. Execute settlement to swap collateral
///      3. Enable new collateral vault
///      All operations are atomic within EVC batch
contract CowEvcCollateralSwapWrapper is CowWrapper, PreApprovedHashes {
    IEVC public immutable EVC;

    /// @dev The EIP-712 domain type hash used for computing the domain
    /// separator.
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 private constant DOMAIN_NAME = keccak256("CowEvcCollateralSwapWrapper");

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
    bytes32 public immutable domainSeparator;

    string public constant name = "Euler EVC - Collateral Swap";

    uint256 public immutable nonceNamespace;

    error Unauthorized(address msgSender);
    error OperationDeadlineExceeded(uint256 validToTimestamp, uint256 currentTimestamp);
    error PricesNotFoundInSettlement();

    constructor(address _evc, CowSettlement _settlement) CowWrapper(_settlement) {
        EVC = IEVC(_evc);
        nonceNamespace = uint256(uint160(address(this)));

        domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPE_HASH,
                DOMAIN_NAME,
                DOMAIN_VERSION,
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice A command to swap collateral between vaults
     * @dev This structure is used, combined with domain separator, to indicate a pre-approved hash.
     * the `deadline` is used for deduplication checking, so be careful to ensure this value is unique.
     */
    struct CollateralSwapParams {
        /**
         * @dev The ethereum address that has permission to operate upon the account
         */
        address owner;

        /**
         * @dev The subaccount to swap collateral from. Learn more about Euler subaccounts https://evc.wtf/docs/concepts/internals/sub-accounts
         */
        address account;

        /**
         * @dev A date by which this operation must be completed
         */
        uint256 deadline;

        /**
         * @dev The source collateral vault (what we're swapping from)
         */
        address fromVault;

        /**
         * @dev The destination collateral vault (what we're swapping to)
         */
        address toVault;

        /**
         * @dev The amount of collateral to swap from the source vault
         */
        uint256 swapAmount;

        /**
         * @dev Effectively determines whether this is an exactIn or exactOut order. Must be either KIND_BUY or KIND_SELL as defined in GPv2Order. Should be the same as whats in the actual order.
         */
        bytes32 kind;
    }

    function _parseCollateralSwapParams(bytes calldata wrapperData)
        internal
        pure
        returns (CollateralSwapParams memory params, bytes memory signature, bytes calldata remainingWrapperData)
    {
        (params, signature) = abi.decode(wrapperData, (CollateralSwapParams, bytes));

        // Calculate consumed bytes for abi.encode(CollateralSwapParams, bytes)
        // Structure:
        // - 32 bytes: offset to params (0x40)
        // - 32 bytes: offset to signature
        // - 224 bytes: params data (7 fields × 32 bytes)
        // - 32 bytes: signature length
        // - N bytes: signature data (padded to 32-byte boundary)
        uint256 consumed = 224 + 64 + ((signature.length + 31) & ~uint256(31));

        remainingWrapperData = wrapperData[consumed:];
    }

    /// @notice Helper function to compute the hash that would be approved
    /// @param params The CollateralSwapParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(CollateralSwapParams memory params) external view returns (bytes32) {
        return _getApprovalHash(params);
    }

    function _getApprovalHash(CollateralSwapParams memory params) internal view returns (bytes32 digest) {
        bytes32 structHash = keccak256(abi.encode(params));
        bytes32 separator = domainSeparator;
        assembly ("memory-safe") {
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
        (,, remainingWrapperData) = _parseCollateralSwapParams(wrapperData);
    }

    function getSignedCalldata(CollateralSwapParams memory params) external view returns (bytes memory) {
        return abi.encodeCall(IEVC.batch, _getSignedCalldata(params));
    }

    function _getSignedCalldata(CollateralSwapParams memory params)
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
        (params, signature, ) = _parseCollateralSwapParams(wrapperData);

        // Check if the signed calldata hash is pre-approved
        IEVC.BatchItem[] memory signedItems = _getSignedCalldata(params);
        bool isPreApproved = _consumePreApprovedHash(params.owner, _getApprovalHash(params));

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
                        uint256(nonceNamespace),
                        EVC.getNonce(bytes19(bytes20(params.owner)), nonceNamespace),
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
            for (; itemIndex < signedItems.length; itemIndex++) {
                items[itemIndex] = signedItems[itemIndex];
            }
        }

        // 2. Settlement call
        items[itemIndex] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSwap, (settleData, wrapperData, remainingWrapperData))
        });

        // 3. Account status check (automatically done by EVC at end of batch)
        // For more info, see: https://evc.wtf/docs/concepts/internals/account-status-checks
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);
    }

    function _findRatePrices(bytes calldata settleData, address fromVault, address toVault)
        internal
        pure
        returns (uint256 fromVaultPrice, uint256 toVaultPrice)
    {
        (address[] memory tokens, uint256[] memory clearingPrices,,) = abi.decode(
            settleData[4:], (address[], uint256[], CowSettlement.CowTradeData[], CowSettlement.CowInteractionData[][3])
        );
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == fromVault) {
                fromVaultPrice = clearingPrices[i];
            } else if (tokens[i] == toVault) {
                toVaultPrice = clearingPrices[i];
            }
        }
        require(fromVaultPrice != 0 && toVaultPrice != 0, PricesNotFoundInSettlement());
    }

    /// @notice Internal swap function called by EVC
    function evcInternalSwap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        external
        payable
    {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));

        CollateralSwapParams memory params;
        (params, , ) = _parseCollateralSwapParams(wrapperData);
        _evcInternalSwap(settleData, remainingWrapperData, params);
    }

    function _evcInternalSwap(
        bytes calldata settleData,
        bytes calldata remainingWrapperData,
        CollateralSwapParams memory params
    ) internal {
        // If a subaccount is being used, we need to transfer the required amount of collateral for the trade into the owner's wallet.
        // This is required because the settlement contract can only pull funds from the wallet that signed the transaction.
        // Since it's not possible for a subaccount to sign a transaction due to the private key not existing and there being no
        // contract deployed to the subaccount address, transferring to the owner's account is the only option.
        // Additionally, we don't transfer this collateral directly to the settlement contract because the settlement contract
        // requires receiving of funds from the user's wallet, and cannot be put in the contract in advance.
        if (params.owner != params.account) {
            (uint256 fromVaultPrice, uint256 toVaultPrice) =
                _findRatePrices(settleData, params.fromVault, params.toVault);
            uint256 transferAmount = params.swapAmount;
            if (params.kind == KIND_BUY) {
                transferAmount = transferAmount * fromVaultPrice / toVaultPrice;
            }
            SafeERC20Lib.safeTransferFrom(
                IERC20(params.fromVault), params.account, params.owner, transferAmount, address(0)
            );
        }

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        _internalSettle(settleData, remainingWrapperData);
    }
}
