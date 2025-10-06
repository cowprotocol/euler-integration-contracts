// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {GPv2Signing, IERC20, GPv2Trade, GPv2Order} from "cow/mixins/GPv2Signing.sol";
import {GPv2Settlement} from "cow/GPv2Settlement.sol";
import {CowWrapper, GPv2Interaction, GPv2Authentication} from "./vendor/CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

import "forge-std/console.sol";

/// @title CowEvcWrapper
/// @notice A wrapper around the EVC that allows for settlement operations
contract CowEvcWrapper is CowWrapper, GPv2Signing {
    IEVC public immutable EVC;

    /// @notice 0 = not executing, 1 = wrappedSettle() called and not yet internal settle, 2 = evcInternalSettle() called
    uint256 public transient settleState;

    mapping(bytes32 => IEVC.BatchItem[]) private postActions;

    error Unauthorized(address msgSender);
    error NoReentrancy();
    error MultiplePossibleReceivers(
        address resolvedVault, address resolvedSender, address secondVault, address secondSender
    );
    error PostActionsAlreadySet(bytes32 orderDigest, uint256 existingActionsCount);

    error NotEVCSettlement();

    constructor(address _evc, GPv2Authentication _authentication) CowWrapper(_authentication) {
        EVC = IEVC(_evc);
    }

    struct ResolvedValues {
        address vault;
        address sender;
        uint256 minAmount;
    }

    function setRequiredPostActions(bytes32 orderDigest, IEVC.BatchItem[] calldata actions) external {
        // TODO: anyone who knows the order ID can set this function (need to restrict to solvers)
        if (postActions[orderDigest].length > 0) {
            revert PostActionsAlreadySet(orderDigest, postActions[orderDigest].length);
        }
        for (uint256 i = 0;i < actions.length;i++) {
            postActions[orderDigest].push(actions[i]);
        }
    }

    function executePostActions(bytes32 orderDigest) external {
        if (postActions[orderDigest].length > 0) {
            EVC.batch(postActions[orderDigest]);
            //postActions[orderDigest] = new IEVC.BatchItem[](0);
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
    /// @param tokens Tokens involved in settlement
    /// @param clearingPrices Clearing prices for settlement
    /// @param trades Trade data for settlement
    /// @param interactions Interaction data for settlement
    /// @param wrapperData Additional data for any wrappers
    function _wrap(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrapperData
    ) internal override {
        // prevent reentrancy: there is no reason why we would want to allow it here
        if (settleState != 0) {
            revert NoReentrancy();
        }
        settleState = 1;

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
            new IEVC.BatchItem[](preSettlementItems.length + postSettlementItems.length + 1 + trades.length);

        // Copy pre-settlement items
        for (uint256 i = 0; i < preSettlementItems.length; i++) {
            items[i] = preSettlementItems[i];
        }

        // Add settlement call to wrapper - use _internalSettle from GPv2Wrapper
        items[preSettlementItems.length] = IEVC.BatchItem({
            onBehalfOfAccount: msg.sender,
            targetContract: address(this),
            value: 0,
            data: abi.encodePacked(abi.encodeCall(this.evcInternalSettle, (tokens, clearingPrices, trades, interactions)), wrapperData)
        });

        // Copy post-settlement items
        for (uint256 i = 0; i < postSettlementItems.length; i++) {
            items[preSettlementItems.length + 1 + i] = postSettlementItems[i];
        }

        postSettlementItems = processPostActions(tokens, trades, wrapperData);
        for (uint256 i = 0;i < postSettlementItems.length;i++) {
            items[items.length - 1 - i] = postSettlementItems[postSettlementItems.length - 1 - i];
        }

        // Execute all items in a single batch
        EVC.batch(items);
        settleState = 0;
    }

    function processPostActions(IERC20[] calldata tokens, GPv2Trade.Data[] calldata trades, bytes calldata wrapperData) internal view returns (IEVC.BatchItem[] memory newPostActions) {
        // Users can force post settlement actions to also occur in `preSettlementItems`. So we call ourself to enforce this
        address payable finalSettlement = abi.decode(wrapperData[wrapperData.length - 32:wrapperData.length], (address));
        GPv2Order.Data memory o;
        newPostActions = new IEVC.BatchItem[](trades.length);
        for (uint256 i = 0; i < trades.length; i++) {
            GPv2Trade.extractOrder(trades[i], tokens, o);
            bytes32 orderDigest = GPv2Order.hash(
                o,
                GPv2Settlement(finalSettlement).domainSeparator() // TODO can be more efficient
            );
            newPostActions[i] = IEVC.BatchItem({
                onBehalfOfAccount: address(this),
                targetContract: address(this),
                value: 0,
                data: abi.encodeCall(this.executePostActions, (orderDigest))
            });
        }
    }

    /// @notice Internal settlement function called by EVC
    /// @param tokens Tokens involved in settlement
    /// @param clearingPrices Clearing prices for settlement
    /// @param trades Trade data for settlement
    /// @param interactions Interaction data for settlement
    function evcInternalSettle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external payable {
        if (msg.sender != address(EVC)) {
            revert Unauthorized(msg.sender);
        }

        (, uint256 endSettleData) = _settleCalldataLength(tokens, interactions);
        bytes calldata wrapperData = msg.data[endSettleData:];

        if (settleState != 1) {
            // origSender will be address(0) here which indiates that internal settle was called when it shouldn't be (outside of wrappedSettle call)
            revert Unauthorized(address(0));
        }

        settleState = 2;

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        _internalSettle(tokens, clearingPrices, trades, interactions, wrapperData);
    }
}
