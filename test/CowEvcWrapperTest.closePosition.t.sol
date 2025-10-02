// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import "./CowEvcWrapperTest.openPosition.t.sol";

contract CowEvcWrapperClosePositionTest is CowEvcWrapperOpenPositionTest {
    function test_LeverageClose() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        // use the open test to get an open order that we can close
        test_LeverageOpen();

        uint256 SUSDS_MARGIN = 2000e18;

        vm.startPrank(user);

        // Create order parameters
        uint256 sellAmount = 1e18; // 999 eSUSDS 
        uint256 buyAmount = 0.98e18; //  0.98 ETH (permitting a bit of slippage)

        // Get settlement, that sells WETH for SUSDS
        // NOTE the receiver is the SUSDS vault, because we'll skim the output for the user in post-settlement
        (
            bytes memory orderUid,
            ,
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions
        ) = getLeveragedCloseSettlement(user, user, WETH, eSUSDS, sellAmount, buyAmount);

        // User, pre-approve the order
        console.logBytes(orderUid);
        cowSettlement.setPreSignature(orderUid, true);

        signerECDSA.setPrivateKey(privateKey);

        // User approves SUSDS vault for deposit
        IERC20(SUSDS).approve(eSUSDS, type(uint256).max);

        // Construct a batch with deposit of margin collateral and a borrow
        // TODO user approved CoW vault relayer on WETH, therefore the borrow to user's wallet
        // provides WETH to swap. It should be possible to do it without approval by setting borrow recipient
        // to some trusted contract. EVC wrapper? The next batch item could be approving the relayer.
        // How would an order be signed then?
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](4);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.enableCollateral, (user, eSUSDS))
        });
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.enableController, (user, eWETH))
        });
        items[2] = IEVC.BatchItem({
            onBehalfOfAccount: user,
            targetContract: eSUSDS,
            value: 0,
            data: abi.encodeCall(IERC4626.deposit, (SUSDS_MARGIN, user))
        });
        items[3] = IEVC.BatchItem({
            onBehalfOfAccount: user,
            targetContract: eWETH,
            value: 0,
            data: abi.encodeCall(IBorrowing.borrow, (sellAmount, user))
        });

        // User signs the batch
        bytes memory batchData = abi.encodeCall(IEVC.batch, items);
        bytes memory batchSignature =
            signerECDSA.signPermit(user, address(wrapper), 0, 0, block.timestamp, 0, batchData);

        vm.stopPrank();

        // pre-settlement will include nested batch signed and executed through `EVC.permit`
        IEVC.BatchItem[] memory preSettlementItems = new IEVC.BatchItem[](1);
        preSettlementItems[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (user, address(wrapper), 0, 0, block.timestamp, 0, batchData, batchSignature))
        });

        // post-settlement will check slippage and skim the free cash on the destination vault for the user
        IEVC.BatchItem[] memory postSettlementItems = new IEVC.BatchItem[](0);

        // Execute the settlement through the wrapper
        vm.stopPrank();

        {
            address[] memory targets = new address[](1);
            bytes[] memory datas = new bytes[](1);
            bytes memory evcActions = abi.encode(preSettlementItems, postSettlementItems);
            targets[0] = address(wrapper);
            datas[0] = abi.encodeWithSelector(
                wrapper.wrappedSettle.selector, tokens, clearingPrices, trades, interactions, evcActions
            );
            solver.runBatch(targets, datas);

        }

        // Verify the position was created
        assertApproxEqAbs(
            IEVault(eSUSDS).convertToAssets(IERC20(eSUSDS).balanceOf(user)),
            buyAmount + SUSDS_MARGIN,
            1 ether, // rounding in favor of the vault during deposits
            "User should receive eSUSDS"
        );
        assertEq(IEVault(eWETH).debtOf(user), sellAmount, "User should receive eWETH debt");

        // uint256 susdsBalanceInMilkSwapAfter = IERC20(SUSDS).balanceOf(address(milkSwap));
        // assertEq(susdsBalanceInMilkSwapAfter, susdsBalanceInMilkSwapBefore - buyAmount, "MilkSwap should have less SUSDS");
    }

}
