// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order, IERC20 as CowERC20} from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcClosePositionWrapper} from "../src/CowEvcClosePositionWrapper.sol";
import {CowSettlement, CowWrapper} from "../src/vendor/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {PreApprovedHashes} from "../src/PreApprovedHashes.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcClosePositionWrapper
/// @notice Tests the full flow of closing a leveraged position using the new wrapper contract
contract CowEvcClosePositionWrapperTest is CowBaseTest {
    CowEvcClosePositionWrapper public closePositionWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant SUSDS_MARGIN = 2000e18;

    function setUp() public override {
        super.setUp();

        // Deploy the new close position wrapper
        closePositionWrapper = new CowEvcClosePositionWrapper(address(evc), COW_SETTLEMENT);

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(closePositionWrapper));
        vm.stopPrank();

        ecdsa = new SignerECDSA(evc);

        // sUSDS is not currently a collateral for WETH borrow, fix it
        vm.startPrank(IEVault(EWETH).governorAdmin());
        IEVault(EWETH).setLTV(ESUSDS, 0.9e4, 0.9e4, 0);
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
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);

        // Enable collateral and controller on the account
        evc.enableCollateral(account, ESUSDS);
        evc.enableController(account, EWETH);

        // Deposit collateral to the account
        IERC4626(ESUSDS).deposit(collateralAmount, account);

        vm.stopPrank();

        // Borrow assets from the account (needs to be called with account as onBehalfOf)
        vm.startPrank(account);
        IBorrowing(EWETH).borrow(borrowAmount, address(this));

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
        r.interactions = [
            new CowSettlement.CowInteractionData[](0),
            new CowSettlement.CowInteractionData[](2),
            new CowSettlement.CowInteractionData[](0)
        ];
        r.interactions[1][0] = getWithdrawInteraction(sellVaultToken, buyAmount * r.clearingPrices[1] / 1e18);
        r.interactions[1][1] = getSwapInteraction(
            IERC4626(sellVaultToken).asset(), buyToRepayToken, buyAmount * r.clearingPrices[1] / 1e18
        );
    }

    /// @notice Test closing a leveraged position using the new wrapper
    function test_ClosePositionWrapper_SuccessFullRepay() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 collateralAmount = SUSDS_MARGIN + 999e18; // The original margin plus the amount we would have if we sold the borrow amount into ESUSDS

        // First, set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        // Verify position exists
        address account = address(uint160(user) ^ uint8(0x01));
        uint256 debtBefore = IEVault(EWETH).debtOf(account);
        assertEq(debtBefore, borrowAmount, "Position should have debt");

        uint256 sellAmount = 1002 ether; // Sell up to 1002 ESUSDS (buffer)
        uint256 buyAmount = 1.001 ether; // Buy exactly 1.001 WETH to repay debt (a small amount will be returned to user)

        // Get settlement data
        SettlementData memory settlement =
            getClosePositionSettlement(user, user, ESUSDS, WETH, sellAmount, buyAmount);

        // Prepare ClosePositionParams
        uint256 deadline = block.timestamp + 1 hours;
        ecdsa.setPrivateKey(privateKey);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: deadline,
            borrowVault: EWETH,
            collateralVault: ESUSDS,
            collateralAmount: sellAmount,
            repayAmount: buyAmount,
            kind: GPv2Order.KIND_BUY
        });

        // Now close the position
        vm.startPrank(user);

        // User signs the order on cowswap
        // Possibly skippable with Permit2 flow
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

        // For subaccount, user approves transfer of vault shares from the account
        // only required if the approve has not already been granted
        {
            IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
            items[0] = IEVC.BatchItem({
                onBehalfOfAccount: account,
                targetContract: ESUSDS,
                value: 0,
                data: abi.encodeCall(IERC20.approve, (address(closePositionWrapper), type(uint256).max))
            });
            evc.batch(items);
        }

        // User approves vault shares for settlement
        // only required if the approve has not already been granted. Could be skipped with a Permit2 flow
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // User approves the wrapper so it can repay
        IERC20(WETH).approve(address(closePositionWrapper), type(uint256).max);

        // Sign permit for EVC operator (absolutely required in some form or another)
        bytes memory permitSignature = ecdsa.signPermit(
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
        uint256 collateralBefore = IERC20(ESUSDS).balanceOf(user);
        uint256 collateralBeforeAccount = IERC20(ESUSDS).balanceOf(account);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );

        // Encode wrapper data with ClosePositionParams
        bytes memory wrapperData = abi.encode(params, permitSignature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(closePositionWrapper);
        datas[0] = abi.encodeCall(closePositionWrapper.wrappedSettle, (settleData, wrapperData));

        solver.runBatch(targets, datas);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");
        assertLt(
            IERC20(ESUSDS).balanceOf(account), collateralBeforeAccount, "User should have less collateral after closing"
        );
        assertGt(IERC20(ESUSDS).balanceOf(account), 0, "User should have some collateral remaining");
        // the sold collateral is sent through the user's main account, but there should be no balance there
        assertEq(IERC20(ESUSDS).balanceOf(user), collateralBefore, "User main account balance should not have changed");
    }

    /// @notice Test that unauthorized users cannot call evcInternalSettle directly
    function test_ClosePositionWrapper_UnauthorizedInternalSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call evcInternalSettle directly (not through EVC)
        vm.expectRevert(abi.encodeWithSelector(CowEvcClosePositionWrapper.Unauthorized.selector, address(this)));
        closePositionWrapper.evcInternalSettle(settleData, wrapperData, wrapperData);
    }

    /// @notice Test that non-solvers cannot call wrappedSettle
    function test_ClosePositionWrapper_NonSolverCannotSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        // Try to call wrappedSettle as non-solver
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, address(this)));
        closePositionWrapper.wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test closing position with partial repayment
    function test_ClosePositionWrapper_PartialRepay() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 2e18; // Borrow 2 WETH
        uint256 collateralAmount = SUSDS_MARGIN + 3998e18; // Sufficient collateral for 2 WETH borrow (double the margin + borrow amount equivalent)

        // First, set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        vm.startPrank(user);

        // Close only half the position
        uint256 sellAmount = 1000e18; // Sell exactly 1000 ESUSDS (buffer)
        uint256 buyAmount = 0.98e18; // Buy at least 0.98 WETH to repay around half the debt

        // Get settlement data
        SettlementData memory settlement =
            getClosePositionSettlement(user, user, ESUSDS, WETH, sellAmount, buyAmount);

        // User pre-approves the order
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // User approves spending of funds from the close position wrapper
        IERC20(WETH).approve(address(closePositionWrapper), type(uint256).max);

        // Prepare ClosePositionParams with partial repayment
        uint256 deadline = block.timestamp + 1 hours;
        ecdsa.setPrivateKey(privateKey);

        address account = address(uint160(user) ^ uint8(0x01));

        // For subaccount, user approves transfer of vault shares from the account
        {
            IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
            items[0] = IEVC.BatchItem({
                onBehalfOfAccount: account,
                targetContract: ESUSDS,
                value: 0,
                data: abi.encodeCall(IERC20.approve, (address(closePositionWrapper), type(uint256).max))
            });
            evc.batch(items);
        }

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: deadline,
            borrowVault: EWETH,
            collateralVault: ESUSDS,
            collateralAmount: sellAmount,
            repayAmount: buyAmount,
            kind: GPv2Order.KIND_SELL // use KIND_SELL here because that is the generally expected pattern for a partial sell type of order
        });

        bytes memory permitSignature = ecdsa.signPermit(
            user,
            address(closePositionWrapper),
            uint256(uint160(address(closePositionWrapper))),
            0,
            deadline,
            0,
            closePositionWrapper.getSignedCalldata(params)
        );

        vm.stopPrank();

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = abi.encode(params, permitSignature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(closePositionWrapper);
        datas[0] = abi.encodeCall(closePositionWrapper.wrappedSettle, (settleData, wrapperData));

        solver.runBatch(targets, datas);

        // Verify partial repayment
        uint256 debtAfter = IEVault(EWETH).debtOf(account);
        assertApproxEqAbs(debtAfter, borrowAmount - buyAmount, 0.01e18, "Debt should be reduced by repaid amount");
        assertEq(IERC20(WETH).balanceOf(user), 0, "User should have used any collateral they received to repay");
    }

    /// @notice Test parseWrapperData function
    function test_ClosePositionWrapper_ParseWrapperData() external view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: address(uint160(user) ^ uint8(0x01)),
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: ESUSDS,
            collateralAmount: 0,
            repayAmount: type(uint256).max,
            kind: GPv2Order.KIND_BUY
        });

        bytes memory wrapperData = abi.encode(params, new bytes(65));
        bytes memory remainingData = closePositionWrapper.parseWrapperData(wrapperData);

        // After parsing ClosePositionParams, remaining data should be empty
        assertEq(remainingData.length, 0, "Remaining data should be empty");
    }

    /// @notice Test setting pre-approved hash
    function test_ClosePositionWrapper_SetPreApprovedHash() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: address(uint160(user) ^ uint8(0x01)),
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: ESUSDS,
            collateralAmount: 0,
            repayAmount: type(uint256).max,
            kind: GPv2Order.KIND_BUY
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
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 collateralAmount = SUSDS_MARGIN + 999e18;

        // First, set up a leveraged position
        _setupLeveragedPosition(borrowAmount, collateralAmount);

        address account = address(uint160(user) ^ uint8(0x01));

        uint256 sellAmount = 1002 ether;
        uint256 buyAmount = 1.001 ether;

        // Prepare ClosePositionParams
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: ESUSDS,
            collateralAmount: sellAmount,
            repayAmount: buyAmount,
            kind: GPv2Order.KIND_BUY
        });

        // Get settlement data
        SettlementData memory settlement =
            getClosePositionSettlement(user, user, ESUSDS, WETH, sellAmount, buyAmount);

        // Now close the position
        vm.startPrank(user);
        // User approves the wrapper to be operator (both of the main account and the subaccount)
        // only required if the operator permission was not previously granted to the close wrapper
        evc.setAccountOperator(user, address(closePositionWrapper), true);
        evc.setAccountOperator(account, address(closePositionWrapper), true);

        // User pre-approves the hash on the closePositionWrapper (absolutely required in some form)
        bytes32 hash = closePositionWrapper.getApprovalHash(params);
        closePositionWrapper.setPreApprovedHash(hash, true);

        // User pre-approves the order on CoW
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

        // For subaccount, user approves transfer of vault shares from the account
        {
            IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
            items[0] = IEVC.BatchItem({
                onBehalfOfAccount: account,
                targetContract: ESUSDS,
                value: 0,
                data: abi.encodeCall(IERC20.approve, (address(closePositionWrapper), type(uint256).max))
            });
            evc.batch(items);
        }

        // User approves vault shares for settlement
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // User approves the wrapper so it can repay
        IERC20(WETH).approve(address(closePositionWrapper), type(uint256).max);

        vm.stopPrank();

        // Record balances before closing
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );

        // Encode wrapper data with ClosePositionParams (empty signature since pre-approved)
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(closePositionWrapper);
        datas[0] = abi.encodeCall(closePositionWrapper.wrappedSettle, (settleData, wrapperData));

        solver.runBatch(targets, datas);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");
        assertEq(debtBefore, borrowAmount, "User should have started with debt");
    }
}
