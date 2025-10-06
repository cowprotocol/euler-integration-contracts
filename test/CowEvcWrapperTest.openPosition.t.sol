// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Signing} from "cow/mixins/GPv2Signing.sol";
import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

import {EVaultTestBase} from "euler-vault-kit/test/unit/evault/EVaultTestBase.t.sol";

import {CowEvcWrapper, GPv2Trade, GPv2Interaction} from "../src/CowEvcWrapper.sol";
import {CowWrapper} from "../src/vendor/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
//import {GPv2Settlement} from "cow/GPv2Settlement.sol";

import {IERC20} from "cow/libraries/GPv2Trade.sol";
import {console} from "forge-std/Test.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";

import {SignerECDSA} from "./helpers/SignerECDSA.sol";

import {CowWrapperHelpers} from "./helpers/CowWrapperHelpers.sol";

contract CowEvcWrapperOpenPositionTest is CowBaseTest {
    // Euler vaults

    SignerECDSA internal signerECDSA;
    bytes internal emptySettleActions;

    uint256 constant SUSDS_MARGIN = 2000e18;

    function setUp() public override {
        super.setUp();
        signerECDSA = new SignerECDSA(evc);
        emptySettleActions = abi.encode(new IEVC.BatchItem[](0), new IEVC.BatchItem[](0));

        // sUSDS is not currently a collateral for WETH borrow, fix it
        vm.startPrank(IEVault(eWETH).governorAdmin());
        IEVault(eWETH).setLTV(eSUSDS, 0.9e4, 0.9e4, 0);

        // Setup user with SUSDS
        deal(SUSDS, user, 10000e18);
    }

    struct LeveragedSettlementData {
        bytes orderUid;
        GPv2Order.Data orderData;
        CowWrapperHelpers.SettleCall settlement;
    }

    function getLeveragedOpenSettlement(
        address owner,
        address receiver,
        address sellToken,
        address buyVaultToken,
        uint256 sellAmount,
        uint256 buyAmount
    ) public view returns (LeveragedSettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create order data
        r.orderData = GPv2Order.Data({
            sellToken: IERC20(sellToken),
            buyToken: IERC20(buyVaultToken),
            receiver: receiver,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            appData: bytes32(0),
            feeAmount: 0,
            kind: GPv2Order.KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: GPv2Order.BALANCE_ERC20,
            buyTokenBalance: GPv2Order.BALANCE_ERC20
        });

        // Get order UID for the order
        r.orderUid = getOrderUid(owner, r.orderData);

        // Get trade data
        r.settlement.trades = new GPv2Trade.Data[](1);
        r.settlement.trades[0] = getTradeData(sellAmount, buyAmount, validTo, owner, r.orderData.receiver, false);

        // Get tokens and prices
        (r.settlement.tokens, r.settlement.clearingPrices) = getTokensAndPrices();

        // Setup interactions
        r.settlement.interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](3), new GPv2Interaction.Data[](0)];
        r.settlement.interactions[1][0] = getSwapInteraction(sellToken, IERC4626(buyVaultToken).asset(), sellAmount);
        r.settlement.interactions[1][1] = getDepositInteraction(buyVaultToken, buyAmount + 1 ether);
        r.settlement.interactions[1][2] = getSkimInteraction();
    }

    function _doLeverageOpen(uint256 sellAmount, uint256 buyAmount) internal {
        vm.startPrank(user);

        // Get settlement, that sells WETH for SUSDS
        // NOTE the receiver is the SUSDS vault, because we'll skim the output for the user in post-settlement
        LeveragedSettlementData memory levSettlement =
            getLeveragedOpenSettlement(user, user, WETH, eSUSDS, sellAmount, buyAmount);

        // User, pre-approve the order
        console.logBytes(levSettlement.orderUid);
        cowSettlement.setPreSignature(levSettlement.orderUid, true);

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

        // pre-levSettlement will include nested batch signed and executed through `EVC.permit`
        IEVC.BatchItem[] memory preSettlementItems = new IEVC.BatchItem[](1);
        preSettlementItems[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (user, address(wrapper), 0, 0, block.timestamp, 0, batchData, batchSignature))
        });

        // post-levSettlement will check slippage and skim the free cash on the destination vault for the user
        IEVC.BatchItem[] memory postSettlementItems = new IEVC.BatchItem[](0);

        // Execute the levSettlement through the wrapper
        vm.stopPrank();

        {
            address[] memory wrapperTargets = new address[](1);
            bytes[] memory wrapperDatas = new bytes[](1);

            {
                bytes memory preItemsData = abi.encode(preSettlementItems);
                bytes memory postItemsData = abi.encode(postSettlementItems);
                wrapperTargets[0] = address(wrapper);
                wrapperDatas[0] =
                    abi.encodePacked(preItemsData.length, preItemsData, postItemsData.length, postItemsData);
            }

            address[] memory targets = new address[](1);
            bytes[] memory datas = new bytes[](1);

            (targets[0], datas[0]) = CowWrapperHelpers.encodeWrapperCall(
                wrapperTargets, wrapperDatas, address(cowSettlement), levSettlement.settlement
            );

            solver.runBatch(targets, datas);
        }
    }

    function test_LeverageOpen() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        // Create order parameters
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 999e18; //  999 eSUSDS (1000 SUSDS actually deposited)

        _doLeverageOpen(sellAmount, buyAmount);

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

    function test_leverage_MaliciousSolverDoesntRedepositFull() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 SUSDS_MARGIN = 2000e18;

        vm.startPrank(user);

        // Create order parameters
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 999e18; //  999 eSUSDS

        // Get settlement, that sells WETH for buying SUSDS
        // NOTE the receiver is the SUSDS vault, because we'll skim the output for the user in post-settlement
        LeveragedSettlementData memory levSettlement =
            getLeveragedOpenSettlement(user, user, WETH, eSUSDS, sellAmount, buyAmount);

        // User, pre-approve the order
        console.logBytes(levSettlement.orderUid);
        cowSettlement.setPreSignature(levSettlement.orderUid, true);

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

        // pre-levSettlement will include nested batch signed and executed through `EVC.permit`
        IEVC.BatchItem[] memory preSettlementItems = new IEVC.BatchItem[](1);
        preSettlementItems[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (user, address(wrapper), 0, 0, block.timestamp, 0, batchData, batchSignature))
        });

        // post-levSettlement, first lets assume we don't call the swap verifier
        IEVC.BatchItem[] memory postSettlementItems = new IEVC.BatchItem[](0);

        // Execute the levSettlement through the wrapper
        vm.stopPrank();
        //vm.startPrank(solver);

        {
            address[] memory wrapperTargets = new address[](1);
            bytes[] memory wrapperDatas = new bytes[](1);

            {
                bytes memory preItemsData = abi.encode(preSettlementItems);
                bytes memory postItemsData = abi.encode(postSettlementItems);
                wrapperTargets[0] = address(wrapper);
                wrapperDatas[0] =
                    abi.encodePacked(preItemsData.length, preItemsData, postItemsData.length, postItemsData);
            }

            address[] memory targets = new address[](1);
            bytes[] memory datas = new bytes[](1);

            (targets[0], datas[0]) = CowWrapperHelpers.encodeWrapperCall(
                wrapperTargets, wrapperDatas, address(cowSettlement), levSettlement.settlement
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

    function test_leverage_MaliciousNonSolverCallsInternalSettleDirectly() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 SUSDS_MARGIN = 2000e18;

        vm.startPrank(user);

        // Create order parameters
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 999e18; //  999 eSUSDS

        // Get settlement, that sells WETH for SUSDS
        // NOTE the receiver is the SUSDS vault, because we'll skim the output for the user in post-settlement
        LeveragedSettlementData memory levSettlement =
            getLeveragedOpenSettlement(user, eSUSDS, WETH, eSUSDS, sellAmount, buyAmount);
        cowSettlement.setPreSignature(levSettlement.orderUid, true);

        vm.stopPrank();

        // User approves SUSDS vault for deposit
        IERC20(SUSDS).approve(eSUSDS, type(uint256).max);

        // This contract will be the "malicious" solver. It should not be able to complete the settle flow
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);

        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(
                CowEvcWrapper.evcInternalSettle, (new bytes(0), new bytes(0))
            )
        });

        vm.expectRevert(abi.encodeWithSelector(CowEvcWrapper.Unauthorized.selector, address(0)));
        evc.batch(items);
    }

    function test_leverage_MaliciousNonSolverTriesToDoIt() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 SUSDS_MARGIN = 2000e18;

        vm.startPrank(user);

        // Create order parameters
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 1000e18; //  1000 SUSDS

        // Get settlement, that sells WETH for SUSDS
        // NOTE the receiver is the SUSDS vault, because we'll skim the output for the user in post-settlement
        LeveragedSettlementData memory levSettlement =
            getLeveragedOpenSettlement(user, eSUSDS, WETH, eSUSDS, sellAmount, buyAmount);

        // User, pre-approve the order
        console.logBytes(levSettlement.orderUid);
        cowSettlement.setPreSignature(levSettlement.orderUid, true);

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

        // pre-levSettlement will include nested batch signed and executed through `EVC.permit`
        IEVC.BatchItem[] memory preSettlementItems = new IEVC.BatchItem[](1);
        preSettlementItems[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.permit, (user, address(wrapper), 0, 0, block.timestamp, 0, batchData, batchSignature))
        });

        // post-levSettlement does not need to do anything because the levSettlement contract will automatically verify the amount of remaining funds
        IEVC.BatchItem[] memory postSettlementItems = new IEVC.BatchItem[](0);

        // Execute the levSettlement through the wrapper
        vm.stopPrank();

        // This contract will be the "malicious" solver. It should not be able to complete the settle flow
        //bytes memory evcActions = abi.encode(preSettlementItems, postSettlementItems);

        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, address(this)));
        wrapper.settle(
            levSettlement.settlement.tokens,
            levSettlement.settlement.clearingPrices,
            levSettlement.settlement.trades,
            levSettlement.settlement.interactions
        );
    }
}
