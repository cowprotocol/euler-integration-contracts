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
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    /// @dev The EIP-712 domain name used for computing the domain separator.
    bytes32 private constant DOMAIN_NAME = keccak256("CowEvcClosePositionWrapper");

    /// @dev The EIP-712 domain version used for computing the domain separator.
    bytes32 private constant DOMAIN_VERSION = keccak256("1");

    /// @dev The domain separator used for signing orders that gets mixed in
    /// making signatures for different domains incompatible. This domain
    /// separator is computed following the EIP-712 standard and has replay
    /// protection mixed in so that signed orders are only valid for specific
    /// this contract.
    bytes32 public immutable domainSeparator;

    string public constant name = "Euler EVC - Close Position";

    /// @notice Tracks the number of times this wrapper has been called
    uint256 public transient depth;
    /// @notice Tracks the number of times `evcInternalSettle` has been called
    uint256 public transient settleCalls;

    uint256 public immutable nonceNamespace;

    error Unauthorized(address msgSender);
    error OperationDeadlineExceeded(uint256 validToTimestamp, uint256 currentTimestamp);
    error InsufficientRepaymentAsset(address vault, uint256 balanceAmount, uint256 repayAmount);
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
         * @dev The maximum amount of debt to repay. Use a number greater than the actual debt to repay full debt
         */
        uint256 maxRepayAmount;
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
        // - 192 bytes: params data (6 fields × 32 bytes)
        // - 32 bytes: signature length
        // - N bytes: signature data (padded to 32-byte boundary)
        // We can just math this out
        uint256 consumed = 192 + 64 + ((signature.length + 31) & ~uint256(31));

        remainingWrapperData = wrapperData[consumed:];
    }

    /// @notice Helper function to compute the hash that would be approved
    /// @param params The ClosePositionParams to hash
    /// @return The hash of the signed calldata for these params
    function getApprovalHash(ClosePositionParams memory params) external view returns (bytes32) {
        return _getApprovalHash(params);
    }

    function _getApprovalHash(ClosePositionParams memory params) internal view returns (bytes32 digest) {
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
        // get current account debt, and find out if we are repaying all
        uint256 debtAmount = IBorrowing(params.borrowVault).debtOf(params.account);
        bool repayAll = params.maxRepayAmount >= debtAmount;

        items = new IEVC.BatchItem[](repayAll ? 2 : 1);

        // 1. Set account operator to allow this contract to act on behalf of owner
        /*items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.setAccountOperator, (params.account, address(this), true))
        });*/

        // 2. Repay debt and return remaining assets
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: params.account,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.helperRepayAndReturn, (params.borrowVault, params.account, params.maxRepayAmount, repayAll))
        });

        // 3. If we are repaying all, we should disable the collateral from the account
        if (repayAll) {
            items[1] = IEVC.BatchItem({
                onBehalfOfAccount: address(0),
                targetContract: address(EVC),
                value: 0,
                data: abi.encodeCall(IEVC.disableCollateral, (params.account, params.collateralVault))
            });
        }

        // 4. Revoke operator permission
        /*items[repayAll ? 3 : 2] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(EVC),
            value: 0,
            data: abi.encodeCall(IEVC.setAccountOperator, (params.account, address(this), false))
        });*/
    }

    // helper function to execute repay
    function helperRepayAndReturn(address vault, address beneficiary, uint256 maxRepay, bool repayAll) external {
        IERC20 asset = IERC20(IERC4626(vault).asset());

        // the settlement contract should have sent us `maxRepay` money
        // if we dont have enough money, then either:
        // 1. the CowOrder was not configured to correctly give us enough money
        // 2. Somebody else using this wrapper (nesting the wrappers) did #1 (and the solver borked up)
        require(asset.balanceOf(address(this)) >= maxRepay, InsufficientRepaymentAsset(vault, asset.balanceOf(address(this)), maxRepay));

        asset.approve(vault, type(uint256).max);
        uint256 actualRepay = IBorrowing(vault).repay(repayAll ? type(uint256).max : maxRepay, beneficiary);

        // transfer any remaining dust back to the owner
        if (actualRepay < maxRepay) {
            SafeERC20Lib.safeTransfer(asset, beneficiary, maxRepay - actualRepay);
        }
    }

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations to close a position
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data containing ClosePositionParams
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData) internal override {
        depth = depth + 1;

        // Decode wrapper data into ClosePositionParams
        ClosePositionParams memory params;
        bytes memory signature;
        (params, signature, ) = _parseClosePositionParams(wrapperData);

        // Check if the signed calldata hash is pre-approved
        IEVC.BatchItem[] memory signedItems = _getSignedCalldata(params);
        bool isPreApproved = _consumePreApprovedHash(params.owner, _getApprovalHash(params));

        // Calculate the number of items needed
        uint256 baseItemCount = 2;
        uint256 itemCount = isPreApproved ? baseItemCount - 1 + signedItems.length : baseItemCount;

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](itemCount);
        uint256 itemIndex = 0;

        // if its a subaccount, we have to transfer the required tokens to the owner's account first
        /*if (params.account != params.owner) {
            (uint256 collateralVaultPrice, uint256 borrowPrice) =
                _findRatePrices(settleData, params.collateralVault, params.borrowVault);

            uint256 transferAmount = params.maxRepayAmount * borrowPrice / collateralVaultPrice;
            items[itemIndex++] = IEVC.BatchItem({
                onBehalfOfAccount: params.account,
                targetContract: params.collateralVault,
                value: 0,
                data: abi.encodeCall(IERC20(params.collateralVault).transfer, (params.owner, transferAmount))
            });
        }*/

        // Build the EVC batch items for closing a position
        // 1. Settlement call
        items[itemIndex++] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
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
            require(
                params.deadline >= block.timestamp,
                OperationDeadlineExceeded(params.deadline, block.timestamp)
            );
            // copy the operations to execute. we can operate on behalf of the user directly
            uint256 signedItemIndex = 0;
            for (; itemIndex < itemCount; itemIndex++) {
                items[itemIndex] = signedItems[signedItemIndex++];
            }
        }

        // 3. Account status check (automatically done by EVC at end of batch)
        // No explicit item needed - EVC handles this

        // Execute all items in a single batch
        EVC.batch(items);
    }

    function _findRatePrices(bytes calldata settleData, address collateralVault, address borrowVault) internal view returns (uint256 collateralVaultPrice, uint256 borrowPrice) {
        address borrowAsset = IERC4626(borrowVault).asset();
        (address[] memory tokens, uint256[] memory clearingPrices,,) = abi.decode(settleData[4:], (address[], uint256[], CowSettlement.CowTradeData[], CowSettlement.CowInteractionData[][3]));
        for (uint256 i = 0;i < tokens.length;i++) {
            if (tokens[i] == collateralVault) {
                collateralVaultPrice = clearingPrices[i];
            }
            else if (tokens[i] == borrowAsset) {
                borrowPrice = clearingPrices[i];
            }
        }
        require(collateralVaultPrice != 0 && borrowPrice != 0, PricesNotFoundInSettlement());
    }

    /// @notice Internal settlement function called by EVC
    function evcInternalSettle(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData) external payable {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));

        // depth should be > 0 (actively wrapping a settle call) and no settle call should have been performed yet
        require(depth > 0 && settleCalls == 0, Unauthorized(address(0)));

        settleCalls = settleCalls + 1;

        ClosePositionParams memory params;
        (params, , ) = _parseClosePositionParams(wrapperData);
        _evcInternalSettle(settleData, remainingWrapperData, params);
    }

    function _evcInternalSettle(bytes calldata settleData, bytes calldata remainingWrapperData, ClosePositionParams memory params) internal {

        if (params.owner != params.account) {
            (uint256 collateralVaultPrice, uint256 borrowPrice) =
                _findRatePrices(settleData, params.collateralVault, params.borrowVault);
            uint256 transferAmount = params.maxRepayAmount * borrowPrice / collateralVaultPrice;
            SafeERC20Lib.safeTransferFrom(IERC20(params.collateralVault), params.account, params.owner, transferAmount, address(0));
        }

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        // wrapperData is empty since we've already processed it in _wrap
        _internalSettle(settleData, remainingWrapperData);
    }
}
