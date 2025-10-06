// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import "./CowEvcWrapperTest.openPosition.t.sol";

contract CowEvcWrapperClosePositionTest is CowEvcWrapperOpenPositionTest {
    function getLeveragedCloseSettlement(
        address owner,
        address receiver,
        address sellVaultToken,
        address buyToRepayToken,
        uint256 sellAmount,
        uint256 buyAmount
    )
        public
        view
        returns (
            bytes memory orderUid,
            bytes32 orderDigest,
            GPv2Order.Data memory orderData,
            CowWrapperHelpers.SettleCall memory settlement
        )
    {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create order data
        orderData = GPv2Order.Data({
            sellToken: IERC20(sellVaultToken),
            buyToken: IERC20(buyToRepayToken),
            receiver: receiver,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            appData: bytes32(0),
            feeAmount: 0,
            kind: GPv2Order.KIND_BUY,
            partiallyFillable: false,
            sellTokenBalance: GPv2Order.BALANCE_ERC20,
            buyTokenBalance: GPv2Order.BALANCE_ERC20
        });

        // Get order UID for the order
        orderUid = getOrderUid(owner, orderData);
        orderDigest = GPv2Order.hash(orderData, cowSettlement.domainSeparator());

        // Get trade data
        settlement.trades = new GPv2Trade.Data[](1);
        settlement.trades[0] = getTradeData(sellAmount, buyAmount, validTo, owner, orderData.receiver, true);

        // Set tokens and prices
        settlement.tokens = new IERC20[](2);
        settlement.tokens[0] = IERC20(sellVaultToken);
        settlement.tokens[1] = IERC20(buyToRepayToken);

        settlement.clearingPrices = new uint256[](2);
        settlement.clearingPrices[0] = milkSwap.prices(IERC4626(sellVaultToken).asset());
        settlement.clearingPrices[1] = milkSwap.prices(buyToRepayToken);

        // Setup interactions
        settlement.interactions = [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](2), new GPv2Interaction.Data[](0)];
        settlement.interactions[1][0] = getWithdrawInteraction(sellVaultToken, buyAmount * settlement.clearingPrices[1] / 1e18);
        settlement.interactions[1][1] =
            getSwapInteraction(IERC4626(sellVaultToken).asset(), buyToRepayToken, buyAmount * settlement.clearingPrices[1] / 1e18);
        return (orderUid, orderDigest, orderData, settlement);
    }

    event StartPhase(bytes32 phase);

    function test_LeverageClose() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        // use the open test to get an open order that we can close
        _doLeverageOpen(1e18, 999e18);

        emit StartPhase("Actually Close");

        uint256 SUSDS_MARGIN = 2000e18;

        vm.startPrank(user);

        // Create order parameters
        uint256 sellAmount = 1002e18; // 1002 eSUSDS (give a bit of a buffer above the actual sell price)
        uint256 buyAmount = 1e18; //  1 ETH (this is the amount of debt we have)

        // Get settlement, that sells WETH for SUSDS
        // NOTE the receiver is the SUSDS vault, because we'll skim the output for the user in post-settlement
        (
            bytes memory orderUid,
            bytes32 orderDigest,
            GPv2Order.Data memory orderData,
            CowWrapperHelpers.SettleCall memory settlement
        ) = getLeveragedCloseSettlement(user, address(wrapper), eSUSDS, WETH, sellAmount, buyAmount);

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
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        IEVC.BatchItem[] memory requiredPostItems = new IEVC.BatchItem[](1);
        /*items[0] = IEVC.BatchItem({
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
        });*/
        requiredPostItems[0] = IEVC.BatchItem({
            onBehalfOfAccount: user,
            targetContract: address(wrapper),
            value: 0,
            // we want to close the position so max is set to `type(uint256).max`
            data: abi.encodeCall(wrapper.helperRepayAndReturn, (eWETH, user, type(uint256).max))
        });
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: user,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(CowEvcWrapper.setRequiredPostActions, (orderDigest, requiredPostItems))
        });

        // User signs the batch
        bytes memory batchData = abi.encodeCall(IEVC.batch, items);
        bytes memory batchSignature =
        // nonce is set to "1" here because it was already consumed once by opening the order
         signerECDSA.signPermit(user, address(wrapper), 0, 1, block.timestamp, 0, batchData);

        // before unpranking lets approve the settlement contract
        IEVault(eSUSDS).approve(cowSettlement.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // pre-settlement will include nested batch signed and executed through `EVC.permit`
        IEVC.BatchItem[] memory preSettlementItems = new IEVC.BatchItem[](1);
        preSettlementItems[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (user, address(wrapper), 0, 1, block.timestamp, 0, batchData, batchSignature))
        });

        // post-settlement will check slippage and skim the free cash on the destination vault for the user
        IEVC.BatchItem[] memory postSettlementItems = new IEVC.BatchItem[](0);

        // Execute the settlement through the wrapper
        console.log("user balance pre", IEVault(eSUSDS).balanceOf(user));

        {
            address[] memory wrapperTargets = new address[](1);
            bytes[] memory wrapperDatas = new bytes[](1);

            {
                bytes memory preItemsData = abi.encode(preSettlementItems);
                bytes memory postItemsData = abi.encode(postSettlementItems);
                wrapperTargets[0] = address(wrapper);
                wrapperDatas[0] = abi.encodePacked(preItemsData.length, preItemsData, postItemsData.length, postItemsData);
            }

            address[] memory targets = new address[](1);
            bytes[] memory datas = new bytes[](1);

            (targets[0], datas[0]) = CowWrapperHelpers.encodeWrapperCall(
                wrapperTargets,
                wrapperDatas,
                address(cowSettlement),
                settlement
            );

            solver.runBatch(targets, datas);
        }

        // Verify the user received any remainder that might exist
        assertEq(IEVault(eWETH).debtOf(user), 0, "User should have their debt repaid");
        assertApproxEqAbs(
            IEVault(eSUSDS).convertToAssets(IERC20(eSUSDS).balanceOf(user)),
            SUSDS_MARGIN, // basically only the margin should be left
            5 ether, // rounding in favor of the vault during deposits
            "User should receive eSUSDS"
        );

        // uint256 susdsBalanceInMilkSwapAfter = IERC20(SUSDS).balanceOf(address(milkSwap));
        // assertEq(susdsBalanceInMilkSwapAfter, susdsBalanceInMilkSwapBefore - buyAmount, "MilkSwap should have less SUSDS");
    }
}
