// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.30;

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IGPv2Settlement, GPv2Interaction} from "./vendor/interfaces/IGPv2Settlement.sol";
import {IGPv2Authentication} from "./vendor/interfaces/IGPv2Authentication.sol";

import {GPv2Signing, IERC20, GPv2Trade} from "cow/mixins/GPv2Signing.sol";
import {GPv2Wrapper} from "cow/GPv2Wrapper.sol";

import {SwapVerifier} from "./SwapVerifier.sol";

import "forge-std/console.sol";

/// @title CowEvcWrapper
/// @notice A wrapper around the EVC that allows for settlement operations
contract CowEvcWrapper is GPv2Wrapper, GPv2Signing, SwapVerifier {
    IEVC public immutable EVC;

    address public transient origSender;

    error Unauthorized(address msgSender);
    error NoReentrancy();
    error MultiplePossibleReceivers(
        address resolvedVault, address resolvedSender, address secondVault, address secondSender
    );

    error NotEVCSettlement();

    constructor(address _evc, address payable _settlement)
        GPv2Wrapper(_settlement)
    {
        EVC = IEVC(_evc);
    }

    struct ResolvedValues {
        address vault;
        address sender;
        uint256 minAmount;
    }


    /// @notice Implementation of GPv2Wrapper._wrap - executes EVC operations around settlement
    /// @param tokens Tokens involved in settlement
    /// @param clearingPrices Clearing prices for settlement
    /// @param trades Trade data for settlement
    /// @param interactions Interaction data for settlement
    /// @param wrapperData Additional data for the wrapper (unused in this implementation)
    function _wrap(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrapperData
    ) internal override {
        // prevent reentrancy: there is no reason why we would want to allow it here
        if (origSender != address(0)) {
            revert NoReentrancy();
        }
        origSender = msg.sender;

        // Decode wrapperData into pre and post settlement actions
        (IEVC.BatchItem[] memory preSettlementItems, IEVC.BatchItem[] memory postSettlementItems) =
            abi.decode(wrapperData, (IEVC.BatchItem[], IEVC.BatchItem[]));
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](preSettlementItems.length + postSettlementItems.length + 1);

        // Copy pre-settlement items
        for (uint256 i = 0; i < preSettlementItems.length; i++) {
            items[i] = preSettlementItems[i];
            uint256 ptr;
            uint256 ptr2;
            IEVC.BatchItem memory subItem = preSettlementItems[i];
            bytes memory itemsData = preSettlementItems[i].data;
            assembly {
                ptr := itemsData
                ptr2 := subItem
            }
        }

        // Add settlement call to wrapper - use _internalSettle from GPv2Wrapper
        items[preSettlementItems.length] = IEVC.BatchItem({
            onBehalfOfAccount: msg.sender,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (tokens, clearingPrices, trades, interactions))
        });

        // immediately after processing the swap, we should be skimming the result to the user
        // we have to identify the trade associated with the vault to skim
        /*ResolvedValues memory resolved;
        for (uint256 i = 0; i < trades.length; i++) {
            // the trade we are looking for is one where the receiver is the token itself
            // if there are more than one trades that have this pattern, then something wierd is happening and we need to exit
            console.log("check trades", i);
            console.log("recvr", trades[i].receiver);
            console.log("tokens", address(tokens[1]));
            if (trades[i].receiver == address(tokens[trades[i].buyTokenIndex])) {
                // we have to derive from the trade
                RecoveredOrder memory order;
                recoverOrderFromTrade(order, tokens, trades[i]);

                if (resolved.vault != address(0)) {
                    revert MultiplePossibleReceivers(resolved.vault, resolved.sender, trades[i].receiver, order.owner);
                }
                resolved.vault = trades[i].receiver;
                resolved.sender = order.owner;
                resolved.minAmount = trades[i].buyAmount;
            }
        }

        if (resolved.vault == address(0)) {
            revert NotEVCSettlement();
        }

        console.log("resolved vault ", resolved.vault);
        console.log("resolved sender", resolved.sender);
        console.log("resolved minAmount", resolved.minAmount);

        items[preSettlementItems.length + 1] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(
                SwapVerifier.verifyAmountMinAndSkim, (resolved.vault, resolved.sender, resolved.minAmount, block.timestamp)
            )
        });*/

        // Add skim call to the

        // Copy post-settlement items
        for (uint256 i = 0; i < postSettlementItems.length; i++) {
            // At least one of the post settlement items should be skimming back to the user
            items[preSettlementItems.length + 1 + i] = postSettlementItems[i];
        }

        // Execute all items in a single batch
        EVC.batch(items);
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

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        _internalSettle(tokens, clearingPrices, trades, interactions);
    }

}
