// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Signing} from "cow/mixins/GPv2Signing.sol";
import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

import {EVaultTestBase} from "euler-vault-kit/test/unit/evault/EVaultTestBase.t.sol";

import {CowEvcWrapper, GPv2Trade, GPv2Interaction} from "../src/CowEvcWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
//import {GPv2Settlement} from "cow/GPv2Settlement.sol";

import {IERC20} from "cow/libraries/GPv2Trade.sol";
import {console} from "forge-std/Test.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";

import {SignerECDSA} from "./helpers/SignerECDSA.sol";
import {SwapVerifier} from "../src/SwapVerifier.sol";

contract CowEvcWrapperTest is CowBaseTest {
    // Euler vaults

    SignerECDSA internal signerECDSA;
    bytes internal emptySettleActions;

    function setUp() public override {
        super.setUp();
        signerECDSA = new SignerECDSA(evc);
        emptySettleActions = abi.encode(new IEVC.BatchItem[](0), new IEVC.BatchItem[](0));
    }

    /// @dev Helper function to setup LTV for leverage tests
    function _setupLeverageLTV() internal {
        vm.startPrank(IEVault(eWETH).governorAdmin());
        IEVault(eWETH).setLTV(eSUSDS, 0.9e4, 0.9e4, 0);
        vm.stopPrank();
    }

    /// @dev Helper function to create EVC batch items for leverage setup
    function _createLeverageBatchItems(address _user, uint256 susdsMargin, uint256 wethBorrow)
        internal
        view
        returns (IEVC.BatchItem[] memory items)
    {
        items = new IEVC.BatchItem[](4);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.enableCollateral, (_user, eSUSDS))
        });
        items[1] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(IEVC.enableController, (_user, eWETH))
        });
        items[2] = IEVC.BatchItem({
            onBehalfOfAccount: _user,
            targetContract: eSUSDS,
            value: 0,
            data: abi.encodeCall(IERC4626.deposit, (susdsMargin, _user))
        });
        items[3] = IEVC.BatchItem({
            onBehalfOfAccount: _user,
            targetContract: eWETH,
            value: 0,
            data: abi.encodeCall(IBorrowing.borrow, (wethBorrow, _user))
        });
    }

    /// @dev Helper function to setup user and create signed permit batch for leverage
    function _setupUserLeveragePrelude(uint256 susdsMargin, uint256 sellAmount, uint256 buyAmount)
        internal
        returns (
            bytes memory orderUid,
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions,
            IEVC.BatchItem[] memory preSettlementItems
        )
    {
        // Setup user with SUSDS
        deal(SUSDS, user, susdsMargin);

        vm.startPrank(user);

        // Get settlement
        (orderUid,, tokens, clearingPrices, trades, interactions) =
            getSwapSettlement(user, user, sellAmount, buyAmount);

        // User pre-approves the order
        cowSettlement.setPreSignature(orderUid, true);

        signerECDSA.setPrivateKey(privateKey);

        // User approves SUSDS vault for deposit
        IERC20(SUSDS).approve(eSUSDS, type(uint256).max);

        // Create batch items for leverage
        IEVC.BatchItem[] memory items = _createLeverageBatchItems(user, susdsMargin, sellAmount);

        // User signs the batch
        bytes memory batchData = abi.encodeCall(IEVC.batch, items);
        bytes memory batchSignature =
            signerECDSA.signPermit(user, address(wrapper), 0, 0, block.timestamp, 0, batchData);

        vm.stopPrank();

        // pre-settlement includes nested batch signed and executed through `EVC.permit`
        preSettlementItems = new IEVC.BatchItem[](1);
        preSettlementItems[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(0),
            targetContract: address(evc),
            value: 0,
            data: abi.encodeCall(
                IEVC.permit, (user, address(wrapper), 0, 0, block.timestamp, 0, batchData, batchSignature)
            )
        });
    }

    function test_batchWithSettle_Empty() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        (
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions
        ) = getEmptySettlement();

        vm.prank(address(solver));
        wrapper.wrappedSettle(tokens, clearingPrices, trades, interactions, emptySettleActions);
    }

    function test_batchWithSettle_NonSolver() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);
        address nonSolver = makeAddr("nonSolver");
        vm.startPrank(nonSolver);

        (
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions
        ) = getEmptySettlement();

        vm.expectRevert("GPv2Wrapper: not a solver");
        wrapper.wrappedSettle(tokens, clearingPrices, trades, interactions, emptySettleActions);
    }

    function test_batchWithSettle_WithCoWOrder() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);
        uint256 susdsBalanceInMilkSwapBefore = IERC20(SUSDS).balanceOf(address(milkSwap));

        // Setup user with WETH
        deal(WETH, user, 1e18);
        vm.startPrank(user);

        // Create order parameters
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 999e18; //  1000 SUSDS

        // Get settlement, that sells WETH for SUSDS
        (
            bytes memory orderUid,
            ,
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions
        ) = getSwapSettlement(user, user, sellAmount, buyAmount);

        // User, pre-approve the order
        console.logBytes(orderUid);
        cowSettlement.setPreSignature(orderUid, true);

        // Execute the settlement through the wrapper
        vm.stopPrank();
        vm.startPrank(address(solver));

        wrapper.wrappedSettle(tokens, clearingPrices, trades, interactions, emptySettleActions);

        // Verify the swap was executed
        assertEq(IERC20(eSUSDS).balanceOf(user), buyAmount, "User should receive SUSDS");
        assertEq(IERC20(WETH).balanceOf(address(milkSwap)), sellAmount, "MilkSwap should receive WETH");

        uint256 susdsBalanceInMilkSwapAfter = IERC20(SUSDS).balanceOf(address(milkSwap));
        assertEq(
            susdsBalanceInMilkSwapAfter, susdsBalanceInMilkSwapBefore - buyAmount - 1e18, "MilkSwap should have less SUSDS"
        );
    }

    function test_leverage_WithCoWOrder() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        _setupLeverageLTV();

        uint256 SUSDS_MARGIN = 2000e18;
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 999e18; //  999 eSUSDS (1000 SUSDS actually deposited)

        (
            ,
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions,
            IEVC.BatchItem[] memory preSettlementItems
        ) = _setupUserLeveragePrelude(SUSDS_MARGIN, sellAmount, buyAmount);

        // post-settlement will check slippage and skim the free cash on the destination vault for the user
        IEVC.BatchItem[] memory postSettlementItems = new IEVC.BatchItem[](0);

        // Execute the settlement through the wrapper
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        bytes memory evcActions = abi.encode(preSettlementItems, postSettlementItems);
        targets[0] = address(wrapper);
        datas[0] = abi.encodeWithSelector(
            wrapper.wrappedSettle.selector, tokens, clearingPrices, trades, interactions, evcActions
        );
        solver.runBatch(targets, datas);

        // Verify the position was created
        assertApproxEqAbs(
            IEVault(eSUSDS).convertToAssets(IERC20(eSUSDS).balanceOf(user)),
            buyAmount + SUSDS_MARGIN,
            1 ether, // rounding in favor of the vault during deposits
            "User should receive eSUSDS"
        );
        assertEq(IEVault(eWETH).debtOf(user), sellAmount, "User should receive eWETH debt");
    }

    function test_leverage_MaliciousSolverDoesntRedepositFull() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        _setupLeverageLTV();

        uint256 SUSDS_MARGIN = 2000e18;
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 999e18; //  999 eSUSDS

        (
            ,
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions,
            IEVC.BatchItem[] memory preSettlementItems
        ) = _setupUserLeveragePrelude(SUSDS_MARGIN, sellAmount, buyAmount);

        // post-settlement, first lets assume we don't call the swap verifier
        IEVC.BatchItem[] memory postSettlementItems = new IEVC.BatchItem[](0);

        // Execute the settlement through the wrapper
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        bytes memory evcActions = abi.encode(preSettlementItems, postSettlementItems);
        targets[0] = address(wrapper);
        datas[0] = abi.encodeWithSelector(
            wrapper.wrappedSettle.selector, tokens, clearingPrices, trades, interactions, evcActions
        );

        solver.runBatch(targets, datas);

        // Verify the position was created
        assertApproxEqAbs(
            IEVault(eSUSDS).convertToAssets(IERC20(eSUSDS).balanceOf(user)),
            buyAmount + SUSDS_MARGIN,
            1 ether, // rounding in favor of the vault during deposits
            "User should receive eSUSDS"
        );
        assertEq(IEVault(eWETH).debtOf(user), sellAmount, "User should receive eWETH debt");
    }

    function test_leverage_MaliciousNonSolverCallsInternalSettleDirectly() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        _setupLeverageLTV();

        uint256 SUSDS_MARGIN = 2000e18;
        uint256 sellAmount = 1e18; // 1 WETH
        uint256 buyAmount = 999e18; //  999 eSUSDS

        deal(SUSDS, user, SUSDS_MARGIN);

        vm.startPrank(user);

        (bytes memory orderUid,, IERC20[] memory tokens, uint256[] memory clearingPrices, GPv2Trade.Data[] memory trades, GPv2Interaction.Data[][3] memory interactions) =
            getSwapSettlement(user, eSUSDS, sellAmount, buyAmount);
        cowSettlement.setPreSignature(orderUid, true);

        vm.stopPrank();

        IERC20(SUSDS).approve(eSUSDS, type(uint256).max);

        // This contract will be the "malicious" solver. It should not be able to complete the settle flow
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: address(this),
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(CowEvcWrapper.evcInternalSettle, (tokens, clearingPrices, trades, interactions))
        });

        vm.expectRevert(abi.encodeWithSelector(CowEvcWrapper.Unauthorized.selector, address(0)));
        evc.batch(items);
    }

    function test_leverage_MaliciousNonSolverTriesToDoIt() external {
        GPv2Interaction.Data[][3] memory emptyInteractions;
        vm.expectRevert("GPv2Wrapper: not a solver");
        wrapper.wrappedSettle(new IERC20[](0), new uint256[](0), new GPv2Trade.Data[](0), emptyInteractions, new bytes(0));
    }
}
