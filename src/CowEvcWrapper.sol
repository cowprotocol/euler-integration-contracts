// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";
//import {IGPv2Settlement, GPv2Interaction} from "./vendor/interfaces/IGPv2Settlement.sol";
import {IGPv2Authentication} from "./vendor/interfaces/IGPv2Authentication.sol";

import {GPv2Signing, IERC20, GPv2Trade, GPv2Order} from "cow/mixins/GPv2Signing.sol";
import {GPv2Settlement} from "cow/GPv2Settlement.sol";
import {CowWrapper,GPv2Interaction,GPv2Authentication} from "./vendor/CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

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

    error NotEVCSettlement();

    constructor(address _evc, address _authentication) CowWrapper(_authentication) {
        EVC = IEVC(_evc);
    }

    struct ResolvedValues {
        address vault;
        address sender;
        uint256 minAmount;
    }

    function setRequiredPostActions(
        bytes32 orderDigest,
        IEVC.BatchItem[] calldata actions
    ) external {
        postActions[orderDigest] = actions;
    }

    function executePostActions(
        bytes32 orderDigest
    ) external {
        if (postActions[orderDigest].length > 0) {
            EVC.batch(postActions[orderDigest]);
            postActions[orderDigest] = new IEVC.BatchItem[](0);
        }

    }

    // helper function to execute repay
    function helperRepayAndReturn(
        address vault,
        address beneficiary,
        uint256 maxRepay
    ) external {
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
        uint256 preSettlementItemsDataSize = uint256(bytes32(wrapperData[0:32]));
        (IEVC.BatchItem[] memory preSettlementItems) =
            abi.decode(wrapperData[32:preSettlementItemsDataSize], (IEVC.BatchItem[]));
        wrapperData = wrapperData[preSettlementItemsDataSize+32:];

        uint256 postSettlementItemsDataSize = uint256(bytes32(wrapperData[0:32]));
        (IEVC.BatchItem[] memory postSettlementItems) =
            abi.decode(wrapperData[32:postSettlementItemsDataSize], (IEVC.BatchItem[]));
        wrapperData = wrapperData[postSettlementItemsDataSize+32:];


        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](preSettlementItems.length + postSettlementItems.length + 1 + trades.length);

        // Copy pre-settlement items
        for (uint256 i = 0; i < preSettlementItems.length; i++) {
            items[i] = preSettlementItems[i];
        }

        // Add settlement call to wrapper - use _internalSettle from GPv2Wrapper
        items[preSettlementItems.length] = IEVC.BatchItem({
            onBehalfOfAccount: msg.sender,
            targetContract: address(this),
            value: 0,
            data: abi.encodeCall(this.evcInternalSettle, (tokens, clearingPrices, trades, interactions, wrapperData))
        });

        // Copy post-settlement items
        for (uint256 i = 0; i < postSettlementItems.length; i++) {
            items[preSettlementItems.length + 1 + i] = postSettlementItems[i];
        }

        // Users can force post settlement actions to also occur in `preSettlementItems`. So we call ourself to enforce this
        address finalSettlement = abi.decode(wrapperData[wrapperData.length - 32], (address));
        GPv2Order.Data memory o;
        for (uint256 i = 0;i < trades.length;i++) {
            GPv2Trade.extractOrder(trades[i], tokens, o);
            bytes32 orderDigest = GPv2Order.hash(
                o,
                GPv2Settlement(finalSettlement).domainSeparator() // TODO can be more efficient
            );
            items[preSettlementItems.length + postSettlementItems.length + 1 + i] = IEVC.BatchItem({
                onBehalfOfAccount: address(this),
                targetContract: address(this),
                value: 0,
                data: abi.encodeCall(this.executePostActions, (orderDigest))
            });
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
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrapperData
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
