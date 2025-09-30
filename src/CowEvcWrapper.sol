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

    /// @notice 0 = not executing, 1 = wrappedSettle() called and not yet internal settle, 2 = evcInternalSettle() called
    uint256 public transient settleState;

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
        if (settleState != 0) {
            revert NoReentrancy();
        }
        settleState = 1;

        // Decode wrapperData into pre and post settlement actions
        (IEVC.BatchItem[] memory preSettlementItems, IEVC.BatchItem[] memory postSettlementItems) =
            abi.decode(wrapperData, (IEVC.BatchItem[], IEVC.BatchItem[]));
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](preSettlementItems.length + postSettlementItems.length + 1);

        // Copy pre-settlement items
        for (uint256 i = 0; i < preSettlementItems.length; i++) {
            items[i] = preSettlementItems[i];
            /*uint256 ptr;
            uint256 ptr2;
            IEVC.BatchItem memory subItem = preSettlementItems[i];
            bytes memory itemsData = preSettlementItems[i].data;
            assembly {
                ptr := itemsData
                ptr2 := subItem
            }*/
        }

        // Add settlement call to wrapper - use _internalSettle from GPv2Wrapper
        items[preSettlementItems.length] = IEVC.BatchItem({
            onBehalfOfAccount: msg.sender,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (tokens, clearingPrices, trades, interactions))
        });

        // Copy post-settlement items
        for (uint256 i = 0; i < postSettlementItems.length; i++) {
            items[preSettlementItems.length + 1 + i] = postSettlementItems[i];
        }

        // Execute all items in a single batch
        EVC.batch(items);
        settleState = 0;
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

        if (settleState != 1) {
            // origSender will be address(0) here which indiates that internal settle was called when it shouldn't be (outside of wrappedSettle call)
            revert Unauthorized(address(0));
        }

        settleState = 2;

        // Use GPv2Wrapper's _internalSettle to call the settlement contract
        _internalSettle(tokens, clearingPrices, trades, interactions);
    }

}
