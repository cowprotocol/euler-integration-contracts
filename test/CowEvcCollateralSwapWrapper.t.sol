// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order, IERC20 as CowERC20} from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcCollateralSwapWrapper} from "../src/CowEvcCollateralSwapWrapper.sol";
import {CowSettlement, CowWrapper} from "../src/vendor/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcCollateralSwapWrapper
/// @notice Tests the full flow of swapping collateral between vaults
contract CowEvcCollateralSwapWrapperTest is CowBaseTest {
    CowEvcCollateralSwapWrapper public collateralSwapWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant SUSDS_MARGIN = 2000e18;

    function setUp() public override {
        super.setUp();

        // Deploy the collateral swap wrapper
        collateralSwapWrapper = new CowEvcCollateralSwapWrapper(address(evc), COW_SETTLEMENT);

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(collateralSwapWrapper));
        vm.stopPrank();

        ecdsa = new SignerECDSA(evc);

        // sUSDS is not currently a collateral for WETH borrow, fix it
        vm.startPrank(IEVault(EWETH).governorAdmin());
        IEVault(EWETH).setLTV(ESUSDS, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // WBTC is not currently a collateral for WETH borrow, fix it
        vm.startPrank(IEVault(EWETH).governorAdmin());
        IEVault(EWETH).setLTV(EWBTC, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup user with SUSDS
        deal(SUSDS, user, 10000e18);

        // User has approved WBTC for COW Protocol
        address vaultRelayer = COW_SETTLEMENT.vaultRelayer();
        vm.prank(user);
        IERC20(WBTC).approve(vaultRelayer, type(uint256).max);
    }

    /// @notice Helper to set up an initial leveraged position
    /// @dev This creates a position that can then be used in tests
    function _setupLeveragedPosition(uint256 borrowAmount, uint256 collateralAmount) internal {
        address account = address(uint160(user) ^ uint8(0x01));

        vm.startPrank(user);

        // User approves SUSDS vault for deposit
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);

        // Enable collateral and controller on the account
        evc.enableCollateral(account, ESUSDS);
        evc.enableController(account, EWETH);

        // Deposit collateral to the account, and add the approximate amount after swapping the borrowed collateral
        IERC4626(ESUSDS).deposit(collateralAmount + borrowAmount * 2500e18 / 0.99e18, account);

        vm.stopPrank();

        // Borrow assets from the account. And confiscate the borrowed asset (needs to be called with account as onBehalfOf)
        vm.startPrank(account);
        IBorrowing(EWETH).borrow(borrowAmount, address(this));

        vm.stopPrank();
    }

    struct SettlementData {
        bytes orderUid;
        GPv2Order.Data orderData;
        address[] tokens;
        uint256[] clearingPrices;
        CowSettlement.CowTradeData[] trades;
        CowSettlement.CowInteractionData[][3] interactions;
    }

    /// @notice Create settlement data for swapping collateral between vaults
    /// @dev Sells vault shares from one vault to buy shares in another
    function getCollateralSwapSettlement(
        address owner,
        address receiver,
        address sellVaultToken,
        address buyVaultToken,
        uint256 sellAmount,
        uint256 buyAmount
    ) public view returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create order data - using KIND_SELL to sell exact amount of collateral
        r.orderData = GPv2Order.Data({
            sellToken: CowERC20(sellVaultToken),
            buyToken: CowERC20(buyVaultToken),
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

        // Get order UID
        r.orderUid = getOrderUid(owner, r.orderData);

        // Get trade data
        r.trades = new CowSettlement.CowTradeData[](1);
        r.trades[0] = getTradeData(sellAmount, buyAmount, validTo, owner, r.orderData.receiver, false);

        // Get tokens and prices
        r.tokens = new address[](2);
        r.tokens[0] = sellVaultToken;
        r.tokens[1] = buyVaultToken;

        r.clearingPrices = new uint256[](2);
        r.clearingPrices[0] = milkSwap.prices(IERC4626(sellVaultToken).asset());
        r.clearingPrices[1] = milkSwap.prices(IERC4626(buyVaultToken).asset()) * 1 ether / 0.98 ether;

        // Setup interactions - withdraw from sell vault, swap underlying assets, deposit to buy vault
        r.interactions = [
            new CowSettlement.CowInteractionData[](0),
            new CowSettlement.CowInteractionData[](4),
            new CowSettlement.CowInteractionData[](0)
        ];

        // Withdraw from sell vault
        r.interactions[1][0] = getWithdrawInteraction(sellVaultToken, sellAmount);

        // Swap underlying assets
        uint256 swapAmount = sellAmount * 0.999 ether / 1 ether;
        r.interactions[1][1] =
            getSwapInteraction(IERC4626(sellVaultToken).asset(), IERC4626(buyVaultToken).asset(), swapAmount);

        // Deposit to buy vault (transfer underlying to vault)
        uint256 buyUnderlyingAmount =
            sellAmount * r.clearingPrices[0] / milkSwap.prices(IERC4626(buyVaultToken).asset());
        r.interactions[1][2] = getDepositInteraction(buyVaultToken, buyUnderlyingAmount);

        // Skim to mint vault shares to receiver
        r.interactions[1][3] = CowSettlement.CowInteractionData({
            target: buyVaultToken,
            value: 0,
            callData: abi.encodeWithSignature("skim(uint256,address)", type(uint256).max, address(COW_SETTLEMENT))
        });
    }

    /// @notice Test swapping collateral from main account
    function test_CollateralSwapWrapper_MainAccount() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        vm.startPrank(user);

        // User deposits SUSDS collateral
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);
        uint256 depositAmount = 1000e18;
        IERC4626(ESUSDS).deposit(depositAmount, user);

        uint256 sellAmount = 500e18; // Sell 500 ESUSDS
        uint256 buyAmount = 0.0045e8; // Expect to receive ~0.0045 EWBTC (8 decimals)

        // Get settlement data
        SettlementData memory settlement = getCollateralSwapSettlement(
            user,
            user, // Receiver is user since it's main account
            ESUSDS,
            EWBTC,
            sellAmount,
            buyAmount
        );

        // User signs the order on cowswap
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

        // User approves vault shares for settlement
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Record balances before swap
        uint256 susdsBalanceBefore = IERC20(ESUSDS).balanceOf(user);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(user);

        // Prepare CollateralSwapParams
        uint256 deadline = block.timestamp + 1 hours;
        ecdsa.setPrivateKey(privateKey);

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: user,
            account: user, // Main account
            deadline: deadline,
            fromVault: ESUSDS,
            toVault: EWBTC,
            swapAmount: sellAmount,
            kind: GPv2Order.KIND_SELL
        });

        // Sign permit for EVC operator
        bytes memory permitSignature = ecdsa.signPermit(
            user,
            address(collateralSwapWrapper),
            uint256(uint160(address(collateralSwapWrapper))),
            0,
            deadline,
            0,
            collateralSwapWrapper.getSignedCalldata(params)
        );

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );

        // Encode wrapper data with CollateralSwapParams
        bytes memory wrapperData = abi.encode(params, permitSignature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(collateralSwapWrapper);
        datas[0] = abi.encodeCall(collateralSwapWrapper.wrappedSettle, (settleData, wrapperData));

        // Expect the event to be emitted
        vm.expectEmit(true, true, true, true);
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        solver.runBatch(targets, datas);

        // Verify the collateral was swapped successfully
        assertEq(
            IERC20(ESUSDS).balanceOf(user), susdsBalanceBefore - sellAmount, "User should have less ESUSDS after swap"
        );
        assertGt(IERC20(EWBTC).balanceOf(user), wbtcBalanceBefore, "User should have more EWBTC after swap");
    }

    /// @notice Test swapping collateral from subaccount
    function test_CollateralSwapWrapper_Subaccount() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        address account = address(uint160(user) ^ uint8(0x01));

        uint256 sellAmount = 500e18; // Sell 500 ESUSDS
        uint256 buyAmount = 0.0045e8; // Expect to receive ~0.0045 EWBTC (8 decimals)

        // Prepare CollateralSwapParams
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: user,
            account: account, // Subaccount
            deadline: block.timestamp + 1 hours,
            fromVault: ESUSDS,
            toVault: EWBTC,
            swapAmount: sellAmount,
            kind: GPv2Order.KIND_SELL
        });

        vm.startPrank(user);

        // User deposits SUSDS collateral to subaccount
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);
        uint256 depositAmount = 1000e18;
        IERC4626(ESUSDS).deposit(depositAmount, account);

        // Get settlement data - receiver is the subaccount
        SettlementData memory settlement = getCollateralSwapSettlement(
            user,
            account, // Receiver is subaccount
            ESUSDS,
            EWBTC,
            sellAmount,
            buyAmount
        );

        // User signs the order on cowswap
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

        // User approves vault shares for settlement (from main account)
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // For subaccount, user approves transfer of vault shares from the account to main account
        {
            IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
            items[0] = IEVC.BatchItem({
                onBehalfOfAccount: account,
                targetContract: ESUSDS,
                value: 0,
                data: abi.encodeCall(IERC20.approve, (address(collateralSwapWrapper), type(uint256).max))
            });
            evc.batch(items);
        }

        // User approves the wrapper to be operator (both of the main account and the subaccount)
        evc.setAccountOperator(account, address(collateralSwapWrapper), true);

        // User pre-approves the hash for the wrapper operation
        bytes32 hash = collateralSwapWrapper.getApprovalHash(params);
        collateralSwapWrapper.setPreApprovedHash(hash, true);

        vm.stopPrank();

        // Record balances before swap
        uint256 susdsBalanceBefore = IERC20(ESUSDS).balanceOf(account);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(account);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );

        // Encode wrapper data with CollateralSwapParams
        bytes memory signature = new bytes(0); // Empty signature for pre-approved hash
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(collateralSwapWrapper);
        datas[0] = abi.encodeCall(collateralSwapWrapper.wrappedSettle, (settleData, wrapperData));

        // Expect the event to be emitted
        vm.expectEmit(true, true, true, true);
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        solver.runBatch(targets, datas);

        // Verify the collateral was swapped successfully
        assertEq(
            IERC20(ESUSDS).balanceOf(account),
            susdsBalanceBefore - sellAmount,
            "Subaccount should have less ESUSDS after swap"
        );
        assertGt(IERC20(EWBTC).balanceOf(account), wbtcBalanceBefore, "Subaccount should have more EWBTC after swap");

        // Main account balance should remain unchanged (transfer is atomic through settlement)
        assertEq(IERC20(ESUSDS).balanceOf(user), 0, "Main account ESUSDS balance should be 0");
    }

    /// @notice Test that unauthorized users cannot call evcInternalSwap directly
    function test_CollateralSwapWrapper_UnauthorizedInternalSwap() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call evcInternalSwap directly (not through EVC)
        vm.expectRevert(abi.encodeWithSelector(CowEvcCollateralSwapWrapper.Unauthorized.selector, address(this)));
        collateralSwapWrapper.evcInternalSwap(settleData, wrapperData, wrapperData);
    }

    /// @notice Test that non-solvers cannot call wrappedSettle
    function test_CollateralSwapWrapper_NonSolverCannotSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        // Try to call wrappedSettle as non-solver
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, address(this)));
        collateralSwapWrapper.wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test parseWrapperData function
    function test_CollateralSwapWrapper_ParseWrapperData() external view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: user,
            account: address(uint160(user) ^ uint8(0x01)),
            deadline: block.timestamp + 1 hours,
            fromVault: ESUSDS,
            toVault: EWBTC,
            swapAmount: 1000e18,
            kind: GPv2Order.KIND_SELL
        });

        bytes memory signature = new bytes(0);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory remainingData = collateralSwapWrapper.parseWrapperData(wrapperData);

        // After parsing CollateralSwapParams, remaining data should be empty
        assertEq(remainingData.length, 0, "Remaining data should be empty");
    }

    /// @notice Test swapping with a leveraged position (ensuring account health is maintained)
    function test_CollateralSwapWrapper_WithLeveragedPosition() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 collateralAmount = 1000e18;

        // Set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        address account = address(uint160(user) ^ uint8(0x01));

        uint256 sellAmount = 1000 ether + 2500 ether; // Sell 3500 ESUSDS
        uint256 buyAmount = 0.0325e8; // Expect to receive ~0.0325 EWBTC (8 decimals)

        // Prepare CollateralSwapParams
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: user,
            account: account,
            deadline: block.timestamp + 1 hours,
            fromVault: ESUSDS,
            toVault: EWBTC,
            swapAmount: sellAmount,
            kind: GPv2Order.KIND_SELL
        });

        // Now swap some collateral from SUSDS to WBTC (add more WBTC collateral)
        vm.startPrank(user);

        // Get settlement data
        SettlementData memory settlement = getCollateralSwapSettlement(
            user,
            account, // Receiver is subaccount
            ESUSDS,
            EWBTC,
            sellAmount,
            buyAmount
        );

        // User signs the order on cowswap
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

        // User approves vault shares for settlement
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // For subaccount, user approves transfer of vault shares from the account
        {
            IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
            items[0] = IEVC.BatchItem({
                onBehalfOfAccount: account,
                targetContract: ESUSDS,
                value: 0,
                data: abi.encodeCall(IERC20.approve, (address(collateralSwapWrapper), type(uint256).max))
            });
            evc.batch(items);
        }

        // User approves the wrapper to be operator (both of the main account and the subaccount)
        evc.setAccountOperator(account, address(collateralSwapWrapper), true);

        // User pre-approves the hash for the wrapper operation
        bytes32 hash = collateralSwapWrapper.getApprovalHash(params);
        collateralSwapWrapper.setPreApprovedHash(hash, true);

        vm.stopPrank();

        // Record balances and debt before swap
        uint256 susdsBalanceBefore = IERC20(ESUSDS).balanceOf(account);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(account);
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );

        // Encode wrapper data with CollateralSwapParams
        bytes memory signature = new bytes(0); // Empty signature for pre-approved hash
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(collateralSwapWrapper);
        datas[0] = abi.encodeCall(collateralSwapWrapper.wrappedSettle, (settleData, wrapperData));

        // Expect the event to be emitted
        vm.expectEmit(true, true, true, true);
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        solver.runBatch(targets, datas);

        // Verify the collateral was swapped successfully while maintaining debt
        assertEq(
            IERC20(ESUSDS).balanceOf(account),
            susdsBalanceBefore - sellAmount,
            "Account should have less ESUSDS after swap"
        );
        assertGt(IERC20(EWBTC).balanceOf(account), wbtcBalanceBefore, "Account should have more EWBTC after swap");
        assertEq(IEVault(EWETH).debtOf(account), debtBefore, "Debt should remain unchanged after swap");
    }
}
