// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order, IERC20 as CowERC20 } from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcClosePositionWrapper} from "../src/CowEvcClosePositionWrapper.sol";
import {CowAuthentication, CowSettlement} from "../src/vendor/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {PreApprovedHashes} from "../src/PreApprovedHashes.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcClosePositionWrapper
/// @notice Tests the full flow of closing a leveraged position using the new wrapper contract
contract CowEvcClosePositionWrapperTest is CowBaseTest {
    CowEvcClosePositionWrapper public closePositionWrapper;
    SignerECDSA internal signerECDSA;

    uint256 constant SUSDS_MARGIN = 2000e18;

    function setUp() public override {
        super.setUp();

        // Deploy the new close position wrapper
        closePositionWrapper = new CowEvcClosePositionWrapper(
            address(evc),
            CowAuthentication(cowSettlement.authenticator())
        );

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(cowSettlement.authenticator());
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(closePositionWrapper));
        vm.stopPrank();

        signerECDSA = new SignerECDSA(evc);

        // sUSDS is not currently a collateral for WETH borrow, fix it
        vm.startPrank(IEVault(eWETH).governorAdmin());
        IEVault(eWETH).setLTV(eSUSDS, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup user with SUSDS
        deal(SUSDS, user, 10000e18);
    }

    struct SettlementData {
        bytes orderUid;
        GPv2Order.Data orderData;
        address[] tokens;
        uint256[] clearingPrices;
        CowSettlement.CowTradeData[] trades;
        CowSettlement.CowInteractionData[][3] interactions;
    }

    /// @notice Helper to set up an initial leveraged position
    /// @dev This creates a position that can then be closed in the tests
    function _setupLeveragedPosition(uint256 borrowAmount, uint256 collateralAmount) internal {
        address account = address(uint160(user) ^ uint8(0x01));

        vm.startPrank(user);

        // User approves SUSDS vault for deposit
        IERC20(SUSDS).approve(eSUSDS, type(uint256).max);

        // Enable collateral and controller on the account
        evc.enableCollateral(account, eSUSDS);
        evc.enableController(account, eWETH);

        evc.setAccountOperator(account, address(closePositionWrapper), true);

        // Deposit collateral to the account
        IERC4626(eSUSDS).deposit(collateralAmount, account);

        vm.stopPrank();

        // Borrow assets from the account (needs to be called with account as onBehalfOf)
        vm.startPrank(account);
        IBorrowing(eWETH).borrow(borrowAmount, user);

        vm.stopPrank();
    }

    /// @notice Create settlement data for closing a leveraged position
    /// @dev Sells vault shares to buy repayment token (WETH)
    function getClosePositionSettlement(
        address owner,
        address receiver,
        address sellVaultToken,
        address buyToRepayToken,
        uint256 sellAmount,
        uint256 buyAmount
    ) public view returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create order data - using KIND_BUY because we want exact buyAmount to repay
        r.orderData = GPv2Order.Data({
            sellToken: CowERC20(sellVaultToken),
            buyToken: CowERC20(buyToRepayToken),
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

        // Get order UID
        r.orderUid = getOrderUid(owner, r.orderData);

        // Get trade data
        r.trades = new CowSettlement.CowTradeData[](1);
        r.trades[0] = getTradeData(sellAmount, buyAmount, validTo, owner, r.orderData.receiver, true);

        // Get tokens and prices
        r.tokens = new address[](2);
        r.tokens[0] = sellVaultToken;
        r.tokens[1] = buyToRepayToken;

        r.clearingPrices = new uint256[](2);
        r.clearingPrices[0] = milkSwap.prices(IERC4626(sellVaultToken).asset());
        r.clearingPrices[1] = milkSwap.prices(buyToRepayToken);

        // Setup interactions - withdraw from vault, swap to repayment token
        r.interactions = [new CowSettlement.CowInteractionData[](0), new CowSettlement.CowInteractionData[](2), new CowSettlement.CowInteractionData[](0)];
        r.interactions[1][0] = getWithdrawInteraction(sellVaultToken, buyAmount * r.clearingPrices[1] / 1e18);
        r.interactions[1][1] = getSwapInteraction(
            IERC4626(sellVaultToken).asset(),
            buyToRepayToken,
            buyAmount * r.clearingPrices[1] / 1e18
        );
    }

    /// @notice Test closing a leveraged position using the new wrapper
    function test_ClosePositionWrapper_SuccessFullRepay() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 collateralAmount = SUSDS_MARGIN + 999e18; // The original margin plus the amount we would have if we sold the borrow amount into eSUSDS

        // First, set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        // Verify position exists
        address account = address(uint160(user) ^ uint8(0x01));
        uint256 debtBefore = IEVault(eWETH).debtOf(account);
        assertEq(debtBefore, borrowAmount, "Position should have debt");

        vm.startPrank(user);

        // Now close the position
        uint256 sellAmount = 1002 ether; // Sell up to 1002 eSUSDS (buffer)
        uint256 buyAmount = 1.001 ether; // Buy exactly 1.001 WETH to repay debt (a small amount will be returned to user)

        // Get settlement data
        SettlementData memory settlement = getClosePositionSettlement(
            user,
            address(closePositionWrapper),
            eSUSDS,
            WETH,
            sellAmount,
            buyAmount
        );

        // User pre-approves the order
        cowSettlement.setPreSignature(settlement.orderUid, true);

        // User approves vault shares for settlement
        IEVault(eSUSDS).approve(cowSettlement.vaultRelayer(), type(uint256).max);

        // Prepare ClosePositionParams
        uint256 deadline = block.timestamp + 1 hours;
        signerECDSA.setPrivateKey(privateKey);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: deadline,
            borrowVault: eWETH,
            collateralVault: eSUSDS,
            maxRepayAmount: 1.001 ether // A bit extra to repay full debt
        });

        // Sign permit for EVC operator
        bytes memory permitSignature = signerECDSA.signPermit(
            user,
            address(closePositionWrapper),
            uint256(uint160(address(closePositionWrapper))),
            0,
            deadline,
            0,
            closePositionWrapper.getSignedCalldata(params)
        );

        vm.stopPrank();

        // Record balances before closing
        uint256 collateralBefore = IERC20(eSUSDS).balanceOf(user);
        uint256 collateralBeforeAccount = IERC20(eSUSDS).balanceOf(account);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(CowSettlement.settle,
            (
                settlement.tokens,
                settlement.clearingPrices,
                settlement.trades,
                settlement.interactions
            )
        );

        // Encode wrapper data with ClosePositionParams
        bytes memory wrapperData = abi.encodePacked(abi.encode(params, permitSignature), cowSettlement);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(closePositionWrapper);
        datas[0] = abi.encodeCall(
            closePositionWrapper.wrappedSettle,
            (settleData, wrapperData)
        );

        solver.runBatch(targets, datas);

        // Verify the position was closed successfully
        assertEq(
            IEVault(eWETH).debtOf(account),
            0,
            "User should have no debt after closing"
        );
        assertLt(
            IERC20(eSUSDS).balanceOf(account),
            collateralBeforeAccount,
            "User should have less collateral after closing"
        );
        assertGt(
            IERC20(eSUSDS).balanceOf(account),
            0,
            "User should have some collateral remaining"
        );
        // the sold collateral is sent through the user's main account, but there should be no balance there
        assertEq(
            IERC20(eSUSDS).balanceOf(user),
            collateralBefore,
            "User main account balance should not have changed"
        );
    }

    /// @notice Test that unauthorized users cannot call evcInternalSettle directly
    function test_ClosePositionWrapper_UnauthorizedInternalSettle() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call evcInternalSettle directly (not through EVC)
        vm.expectRevert(abi.encodeWithSelector(CowEvcClosePositionWrapper.Unauthorized.selector, address(this)));
        closePositionWrapper.evcInternalSettle(settleData, wrapperData);
    }

    /// @notice Test that non-solvers cannot call wrappedSettle
    function test_ClosePositionWrapper_NonSolverCannotSettle() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call wrappedSettle as non-solver
        vm.expectRevert("GPv2Wrapper: not a solver");
        closePositionWrapper.wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test closing position with partial repayment
    function test_ClosePositionWrapper_PartialRepay() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 borrowAmount = 2e18; // Borrow 2 WETH
        uint256 collateralAmount = SUSDS_MARGIN * 2;

        // First, set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        vm.startPrank(user);

        // Close only half the position
        uint256 sellAmount = 1002e18; // Sell up to 1002 eSUSDS (buffer)
        uint256 buyAmount = 1e18; // Buy 1 WETH to repay half the debt

        // Get settlement data
        SettlementData memory settlement = getClosePositionSettlement(
            user,
            address(closePositionWrapper),
            eSUSDS,
            WETH,
            sellAmount,
            buyAmount
        );

        // User pre-approves the order
        cowSettlement.setPreSignature(settlement.orderUid, true);
        IEVault(eSUSDS).approve(cowSettlement.vaultRelayer(), type(uint256).max);

        // Prepare ClosePositionParams with partial repayment
        uint256 deadline = block.timestamp + 1 hours;
        signerECDSA.setPrivateKey(privateKey);

        address account = address(uint160(user) ^ uint8(0x01));

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: deadline,
            borrowVault: eWETH,
            collateralVault: eSUSDS,
            maxRepayAmount: buyAmount // Repay only the bought amount
        });

        bytes memory permitSignature = signerECDSA.signPermit(
            user,
            address(closePositionWrapper),
            uint256(uint160(address(closePositionWrapper))),
            0,
            deadline,
            0,
            closePositionWrapper.getSignedCalldata(params)
        );

        vm.stopPrank();

        bytes memory settleData = abi.encodeCall(CowSettlement.settle, (
            settlement.tokens,
            settlement.clearingPrices,
            settlement.trades,
            settlement.interactions
        ));
        bytes memory wrapperData = abi.encode(params, permitSignature);

        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(closePositionWrapper);
        datas[0] = abi.encodeCall(
            closePositionWrapper.wrappedSettle,
            (settleData, wrapperData)
        );

        solver.runBatch(targets, datas);

        // Verify partial repayment
        uint256 debtAfter = IEVault(eWETH).debtOf(account);
        assertApproxEqAbs(
            debtAfter,
            borrowAmount - buyAmount,
            0.01e18,
            "Debt should be reduced by repaid amount"
        );
    }

    /// @notice Test that depth tracking works correctly
    function test_ClosePositionWrapper_DepthTracking() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        // Initial depth should be 0
        assertEq(closePositionWrapper.depth(), 0, "Initial depth should be 0");
        assertEq(closePositionWrapper.settleCalls(), 0, "Initial settleCalls should be 0");
    }

    /// @notice Test parseWrapperData function
    function test_ClosePositionWrapper_ParseWrapperData() external {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: address(uint160(user) ^ uint8(0x01)),
            deadline: block.timestamp + 1 hours,
            borrowVault: eWETH,
            collateralVault: eSUSDS,
            maxRepayAmount: type(uint256).max
        });

        bytes memory wrapperData = abi.encode(params, new bytes(65));
        bytes memory remainingData = closePositionWrapper.parseWrapperData(wrapperData);

        // After parsing ClosePositionParams, remaining data should be empty
        assertEq(remainingData.length, 0, "Remaining data should be empty");
    }

    /// @notice Test helperRepayAndReturn function
    function test_ClosePositionWrapper_HelperRepayAndReturn() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = SUSDS_MARGIN;

        // Set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        // Give the wrapper some WETH to repay with
        deal(WETH, address(closePositionWrapper), 2e18);

        address account = address(uint160(user) ^ uint8(0x01));
        uint256 debtBefore = IEVault(eWETH).debtOf(account);

        // Call helperRepayAndReturn through EVC on behalf of account
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: account,
            targetContract: address(closePositionWrapper),
            value: 0,
            data: abi.encodeCall(
                closePositionWrapper.helperRepayAndReturn,
                (eWETH, account, type(uint256).max, true)
            )
        });

        vm.prank(account);
        evc.batch(items);

        // Verify debt was repaid
        assertEq(IEVault(eWETH).debtOf(account), 0, "Debt should be fully repaid");

        // Verify remaining WETH was sent to user
        assertGt(IERC20(WETH).balanceOf(user), 0, "User should receive remaining WETH");
    }

    /// @notice Test attempting to close position with insufficient collateral
    function test_ClosePositionWrapper_InsufficientCollateral() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = 1000e18; // Very small collateral

        // Set up a position with minimal collateral
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        vm.startPrank(user);

        // Try to close by selling more collateral than we have
        uint256 sellAmount = 5000e18; // More than we have
        uint256 buyAmount = 1e18;

        SettlementData memory settlement = getClosePositionSettlement(
            user,
            address(closePositionWrapper),
            eSUSDS,
            WETH,
            sellAmount,
            buyAmount
        );

        cowSettlement.setPreSignature(settlement.orderUid, true);
        IEVault(eSUSDS).approve(cowSettlement.vaultRelayer(), type(uint256).max);

        uint256 deadline = block.timestamp + 1 hours;
        signerECDSA.setPrivateKey(privateKey);

        address account = address(uint160(user) ^ uint8(0x01));

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: deadline,
            borrowVault: eWETH,
            collateralVault: eSUSDS,
            maxRepayAmount: type(uint256).max
        });

        bytes memory permitSignature = signerECDSA.signPermit(
            user,
            address(closePositionWrapper),
            uint256(uint160(address(closePositionWrapper))),
            0,
            deadline,
            0,
            closePositionWrapper.getSignedCalldata(params)
        );

        vm.stopPrank();

        bytes memory settleData = abi.encode(
            settlement.tokens,
            settlement.clearingPrices,
            settlement.trades,
            settlement.interactions
        );
        bytes memory wrapperData = abi.encode(params, permitSignature);

        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(closePositionWrapper);
        datas[0] = abi.encodeCall(
            closePositionWrapper.wrappedSettle,
            (settleData, wrapperData)
        );

        // Should revert due to insufficient balance
        vm.expectRevert();
        solver.runBatch(targets, datas);
    }

    /// @notice Test setting pre-approved hash
    function test_ClosePositionWrapper_SetPreApprovedHash() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: address(uint160(user) ^ uint8(0x01)),
            deadline: block.timestamp + 1 hours,
            borrowVault: eWETH,
            collateralVault: eSUSDS,
            maxRepayAmount: type(uint256).max
        });

        bytes32 hash = closePositionWrapper.getApprovalHash(params);

        // Initially hash should not be approved
        assertEq(closePositionWrapper.preApprovedHashes(user, hash), 0, "Hash should not be approved initially");

        // User pre-approves the hash
        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit PreApprovedHashes.PreApprovedHash(user, hash, true);
        closePositionWrapper.setPreApprovedHash(hash, true);

        // Hash should now be approved
        assertGt(closePositionWrapper.preApprovedHashes(user, hash), 0, "Hash should be approved");

        // User revokes the approval
        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit PreApprovedHashes.PreApprovedHash(user, hash, false);
        closePositionWrapper.setPreApprovedHash(hash, false);

        // Hash should no longer be approved
        assertEq(closePositionWrapper.preApprovedHashes(user, hash), 0, "Hash should not be approved after revocation");
    }

    /// @notice Test closing a position with pre-approved hash (no signature needed)
    function test_ClosePositionWrapper_WithPreApprovedHash() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 collateralAmount = SUSDS_MARGIN + 999e18;

        // First, set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        address account = address(uint160(user) ^ uint8(0x01));

        // Prepare ClosePositionParams
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: block.timestamp + 1 hours,
            borrowVault: eWETH,
            collateralVault: eSUSDS,
            maxRepayAmount: 1.001 ether
        });

        // User pre-approves the hash
        bytes32 hash = closePositionWrapper.getApprovalHash(params);
        vm.prank(user);
        closePositionWrapper.setPreApprovedHash(hash, true);

        vm.startPrank(user);

        // Now close the position
        uint256 sellAmount = 1002 ether;
        uint256 buyAmount = 1.001 ether;

        // Get settlement data
        SettlementData memory settlement = getClosePositionSettlement(
            user,
            address(closePositionWrapper),
            eSUSDS,
            WETH,
            sellAmount,
            buyAmount
        );

        // User pre-approves the order
        cowSettlement.setPreSignature(settlement.orderUid, true);

        // User approves vault shares for settlement
        IEVault(eSUSDS).approve(cowSettlement.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Record balances before closing
        uint256 debtBefore = IEVault(eWETH).debtOf(account);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(CowSettlement.settle,
            (
                settlement.tokens,
                settlement.clearingPrices,
                settlement.trades,
                settlement.interactions
            )
        );

        // Encode wrapper data with ClosePositionParams (empty signature since pre-approved)
        bytes memory wrapperData = abi.encodePacked(abi.encode(params, new bytes(0)), cowSettlement);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(closePositionWrapper);
        datas[0] = abi.encodeCall(
            closePositionWrapper.wrappedSettle,
            (settleData, wrapperData)
        );

        solver.runBatch(targets, datas);

        // Verify the position was closed successfully
        assertEq(
            IEVault(eWETH).debtOf(account),
            0,
            "User should have no debt after closing"
        );
        assertEq(debtBefore, borrowAmount, "User should have started with debt");
    }
}
