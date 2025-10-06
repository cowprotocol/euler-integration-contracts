// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {GPv2Signing, IERC20, GPv2Trade, GPv2Order} from "cow/mixins/GPv2Signing.sol";
import {GPv2Settlement} from "cow/GPv2Settlement.sol";
import {CowWrapper, GPv2Interaction, GPv2Authentication} from "./vendor/CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

import {EVCTransientUtils} from "./EVCTransientUtils.sol";

import "forge-std/console.sol";

/// @title CowEvcWrapper
/// @notice A wrapper around the EVC that allows for settlement operations
contract CowEvcWrapper is CowWrapper, GPv2Signing {
    IEVC public immutable EVC;

    /// @notice Tracks the number of times this wrapper has been called. Used to keep track of effective session data
    uint256 public transient depth;
    /// @notice Tracks the number of times `evcInternalSettle` has been called. It should only be called once in a transaction
    uint256 public transient settleCalls;

    error Unauthorized(address msgSender);
    error NoReentrancy();
    error MultiplePossibleReceivers(
        address resolvedVault, address resolvedSender, address secondVault, address secondSender
    );
    error PostActionsAlreadySet(uint256 callDepth, uint256 existingActionsCount);

    error NotEVCSettlement();

    constructor(address _evc, GPv2Authentication _authentication) CowWrapper(_authentication) {
        EVC = IEVC(_evc);
    }

    struct ResolvedValues {
        address vault;
        address sender;
        uint256 minAmount;
    }

    function setRequiredPostActions(IEVC.BatchItem[] calldata actions) external {
        // this call can only be called only once per wrapper invocation. This ensures if the user specified
        // orders to be executed, they actually happen and cant be overridden by another set of parameters possibly introduced by the solver.
        // we use the `depth` to determine where we are in the call stack
        uint256 postActionsLength = EVCTransientUtils.readFromTransientStorage(keccak256(abi.encodePacked("postActions", depth))).length;
        if (postActionsLength > 0) {
            revert PostActionsAlreadySet(depth, postActionsLength);
        }
        EVCTransientUtils.copyToTransientStorage(actions, keccak256(abi.encodePacked("postActions", depth)));
    }

    function executePostActions(uint256 callDepth) external {
        IEVC.BatchItem[] memory postActions = EVCTransientUtils.readFromTransientStorage(keccak256(abi.encodePacked("postActions", depth)));
        if (postActions.length > 0) {
            EVC.batch(postActions);
        }
    }

    // helper function to execute repay
    function helperRepayAndReturn(address vault, address beneficiary, uint256 maxRepay) external {
        IERC20 asset = IERC20(IERC4626(vault).asset());
        asset.approve(vault, type(uint256).max);
        IBorrowing(vault).repay(maxRepay, beneficiary);

        // transfer any remaining dust back to the user
        asset.transfer(beneficiary, asset.balanceOf(address(this)));
    }

    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations around settlement
    /// @param settleData Data which will be used for the parameters in a call to `CowSettlement.settle`
    /// @param wrapperData Additional data for any wrappers
    function _wrap(bytes calldata settleData, bytes calldata wrapperData) internal override {
        depth = depth + 1;

        // Decode wrapperData into pre and post settlement actions
        // We load the length in advance so we know how much to read and advance
        IEVC.BatchItem[] memory preSettlementItems;
        IEVC.BatchItem[] memory postSettlementItems;
        {
            uint256 preSettlementItemsDataSize = uint256(bytes32(wrapperData[0:32]));
            wrapperData = wrapperData[32:];
            (preSettlementItems) = abi.decode(wrapperData[:preSettlementItemsDataSize], (IEVC.BatchItem[]));
            wrapperData = wrapperData[preSettlementItemsDataSize:];

            uint256 postSettlementItemsDataSize = uint256(bytes32(wrapperData[0:32]));
            wrapperData = wrapperData[32:];
            (postSettlementItems) = abi.decode(wrapperData[:postSettlementItemsDataSize], (IEVC.BatchItem[]));
            wrapperData = wrapperData[postSettlementItemsDataSize:];
        }

        IEVC.BatchItem[] memory items =
            new IEVC.BatchItem[](preSettlementItems.length + postSettlementItems.length + 2);

        // Copy pre-settlement items
        for (uint256 i = 0; i < preSettlementItems.length; i++) {
            items[i] = preSettlementItems[i];
        }

        // Add settlement call to wrapper - use _internalSettle from GPv2Wrapper
        items[preSettlementItems.length] = IEVC.BatchItem({
            onBehalfOfAccount: msg.sender,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (settleData, wrapperData))
        });

        // User forced post settlement items
        items[preSettlementItems.length + 1] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.executePostActions, (depth))
        });

        // Copy post-settlement items
        for (uint256 i = 0; i < postSettlementItems.length; i++) {
            items[preSettlementItems.length + 2 + i] = postSettlementItems[i];
        }

        // Execute all items in a single batch
        EVC.batch(items);
    }

    /// @dev Extracts the order data and signing scheme for the specified trade.
    ///
    /// @param trade The trade.
    /// @param tokens The list of tokens included in the settlement. The token
    /// indices in the trade parameters map to tokens in this array.
    /// @param order The memory location to extract the order data to.
    function extractOrder(
        GPv2Trade.Data memory trade,
        IERC20[] memory tokens,
        GPv2Order.Data memory order
    ) internal pure returns (GPv2Signing.Scheme signingScheme) {
        order.sellToken = tokens[trade.sellTokenIndex];
        order.buyToken = tokens[trade.buyTokenIndex];
        order.receiver = trade.receiver;
        order.sellAmount = trade.sellAmount;
        order.buyAmount = trade.buyAmount;
        order.validTo = trade.validTo;
        order.appData = trade.appData;
        order.feeAmount = trade.feeAmount;
        (
            order.kind,
            order.partiallyFillable,
            order.sellTokenBalance,
            order.buyTokenBalance,
            signingScheme
        ) = extractFlags(trade.flags);
    }

    /// @dev Decodes trade flags.
    ///
    /// Trade flags are used to tightly encode information on how to decode
    /// an order. Examples that directly affect the structure of an order are
    /// the kind of order (either a sell or a buy order) as well as whether the
    /// order is partially fillable or if it is a "fill-or-kill" order. It also
    /// encodes the signature scheme used to validate the order. As the most
    /// likely values are fill-or-kill sell orders by an externally owned
    /// account, the flags are chosen such that `0x00` represents this kind of
    /// order. The flags byte uses the following format:
    ///
    /// ```
    /// bit | 31 ...   | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
    /// ----+----------+-------+---+-------+---+---+
    ///     | reserved | *   * | * | *   * | * | * |
    ///                  |   |   |   |   |   |   |
    ///                  |   |   |   |   |   |   +---- order kind bit, 0 for a sell order
    ///                  |   |   |   |   |   |         and 1 for a buy order
    ///                  |   |   |   |   |   |
    ///                  |   |   |   |   |   +-------- order fill bit, 0 for fill-or-kill
    ///                  |   |   |   |   |             and 1 for a partially fillable order
    ///                  |   |   |   |   |
    ///                  |   |   |   +---+------------ use internal sell token balance bit:
    ///                  |   |   |                     0x: ERC20 token balance
    ///                  |   |   |                     10: external Balancer Vault balance
    ///                  |   |   |                     11: internal Balancer Vault balance
    ///                  |   |   |
    ///                  |   |   +-------------------- use buy token balance bit
    ///                  |   |                         0: ERC20 token balance
    ///                  |   |                         1: internal Balancer Vault balance
    ///                  |   |
    ///                  +---+------------------------ signature scheme bits:
    ///                                                00: EIP-712
    ///                                                01: eth_sign
    ///                                                10: EIP-1271
    ///                                                11: pre_sign
    /// ```
    function extractFlags(
        uint256 flags
    )
        internal
        pure
        returns (
            bytes32 kind,
            bool partiallyFillable,
            bytes32 sellTokenBalance,
            bytes32 buyTokenBalance,
            GPv2Signing.Scheme signingScheme
        )
    {
        if (flags & 0x01 == 0) {
            kind = GPv2Order.KIND_SELL;
        } else {
            kind = GPv2Order.KIND_BUY;
        }
        partiallyFillable = flags & 0x02 != 0;
        if (flags & 0x08 == 0) {
            sellTokenBalance = GPv2Order.BALANCE_ERC20;
        } else if (flags & 0x04 == 0) {
            sellTokenBalance = GPv2Order.BALANCE_EXTERNAL;
        } else {
            sellTokenBalance = GPv2Order.BALANCE_INTERNAL;
        }
        if (flags & 0x10 == 0) {
            buyTokenBalance = GPv2Order.BALANCE_ERC20;
        } else {
            buyTokenBalance = GPv2Order.BALANCE_INTERNAL;
        }

        // NOTE: Take advantage of the fact that Solidity will revert if the
        // following expression does not produce a valid enum value. This means
        // we check here that the leading reserved bits must be 0.
        signingScheme = GPv2Signing.Scheme(flags >> 5);
    }

    /// @notice Internal settlement function called by EVC
    function evcInternalSettle(bytes calldata settleData, bytes calldata wrapperData) external payable {
        if (msg.sender != address(EVC)) {
            revert Unauthorized(msg.sender);
        }

        // depth should be > 0 (actively wrapping a settle call) and no settle call should have been performed yet
        if (depth == 0 || settleCalls != 0) {
            // origSender will be address(0) here which indiates that internal settle was called when it shouldn't be (outside of wrappedSettle call)
            revert Unauthorized(address(0));
        }

        settleCalls = settleCalls + 1;

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        _internalSettle(settleData, wrapperData);
    }
}
