// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order, IERC20 as CowERC20 } from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcOpenPositionWrapper} from "../src/CowEvcOpenPositionWrapper.sol";
import {CowAuthentication, CowSettlement, CowWrapper} from "../src/vendor/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {PreApprovedHashes} from "../src/PreApprovedHashes.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcOpenPositionWrapper
/// @notice Tests the full flow of opening a leveraged position using the new wrapper contract
contract CowEvcOpenPositionWrapperTest is CowBaseTest {
    CowEvcOpenPositionWrapper public openPositionWrapper;
    SignerECDSA internal signerECDSA;

    uint256 constant SUSDS_MARGIN = 2000e18;

    function setUp() public override {
        super.setUp();

        // Deploy the new open position wrapper
        openPositionWrapper = new CowEvcOpenPositionWrapper(
            address(evc),
            cowSettlement
        );

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(cowSettlement.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(openPositionWrapper));
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

    /// @notice Create settlement data for opening a leveraged position
    /// @dev Sells borrowed WETH to buy SUSDS which gets deposited into the vault
    function getOpenPositionSettlement(
        address owner,
        address receiver,
        address sellToken,
        address buyVaultToken,
        uint256 sellAmount,
        uint256 buyAmount
    ) public view returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create order data
        r.orderData = GPv2Order.Data({
            sellToken: CowERC20(sellToken),
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
        (r.tokens, r.clearingPrices) = getTokensAndPrices();

        // Setup interactions - swap WETH to SUSDS, deposit to vault, and skim
        r.interactions = [new CowSettlement.CowInteractionData[](0), new CowSettlement.CowInteractionData[](3), new CowSettlement.CowInteractionData[](0)];
        r.interactions[1][0] = getSwapInteraction(sellToken, IERC4626(buyVaultToken).asset(), sellAmount);
        r.interactions[1][1] = getDepositInteraction(buyVaultToken, buyAmount + 1 ether);
        r.interactions[1][2] = getSkimInteraction();
    }

    /// @notice Test opening a leveraged position using the new wrapper
    function test_OpenPositionWrapper_Success() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 expectedBuyAmount = 999e18; // Expect to receive 999 eSUSDS

        address account = address(uint160(user) ^ 1);

        // Get settlement data
        SettlementData memory settlement = getOpenPositionSettlement(
            user,
            account,
            WETH,
            eSUSDS,
            borrowAmount,
            expectedBuyAmount
        );

        // Prepare OpenPositionParams
        uint256 deadline = block.timestamp + 1 hours;
        signerECDSA.setPrivateKey(privateKey);

        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user,
            account: account,
            deadline: deadline,
            collateralVault: eSUSDS,
            borrowVault: eWETH,
            collateralAmount: SUSDS_MARGIN,
            borrowAmount: borrowAmount
        });

        vm.startPrank(user);

        // User approves SUSDS vault for deposit of the margin. Only required if there is margin to deposit and the user hasn't already approved
        IERC20(SUSDS).approve(eSUSDS, type(uint256).max);

        // User signs (in this case we use setPreSignature. this is just for local testing purposes. Real flow would be a off-chain signature)
        cowSettlement.setPreSignature(settlement.orderUid, true);

        // Sign permit for EVC operator
        bytes memory permitSignature = signerECDSA.signPermit(
            user,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            deadline,
            0,
            openPositionWrapper.getSignedCalldata(params)
        );

        vm.stopPrank();

        // Record balances before
        uint256 susdsBalanceBefore = IERC20(eSUSDS).balanceOf(user);
        uint256 debtBefore = IEVault(eWETH).debtOf(user);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(CowSettlement.settle, (
            settlement.tokens,
            settlement.clearingPrices,
            settlement.trades,
            settlement.interactions
        ));

        // Encode wrapper data with OpenPositionParams
        bytes memory wrapperData = abi.encode(params, permitSignature);

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(openPositionWrapper);
        datas[0] = abi.encodeCall(
            openPositionWrapper.wrappedSettle,
            (settleData, wrapperData)
        );

        solver.runBatch(targets, datas);

        // Verify the position was created successfully
        assertApproxEqAbs(
            IEVault(eSUSDS).convertToAssets(IERC20(eSUSDS).balanceOf(account)),
            expectedBuyAmount + SUSDS_MARGIN,
            1 ether,
            "User should have collateral deposited"
        );
        assertEq(
            IEVault(eWETH).debtOf(account),
            borrowAmount,
            "User should have debt"
        );
        assertEq(debtBefore, 0, "User should start with no debt");
        assertEq(susdsBalanceBefore, 0, "User should start with no eSUSDS");
    }

    /// @notice Test that unauthorized users cannot call evcInternalSettle directly
    function test_OpenPositionWrapper_UnauthorizedInternalSettle() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call evcInternalSettle directly (not through EVC)
        vm.expectRevert(abi.encodeWithSelector(CowEvcOpenPositionWrapper.Unauthorized.selector, address(this)));
        openPositionWrapper.evcInternalSettle(settleData, wrapperData);
    }

    /// @notice Test that non-solvers cannot call wrappedSettle
    function test_OpenPositionWrapper_NonSolverCannotSettle() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call wrappedSettle as non-solver
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, address(this)));
        openPositionWrapper.wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test that depth tracking works correctly
    function test_OpenPositionWrapper_DepthTracking() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        // Initial depth should be 0
        assertEq(openPositionWrapper.depth(), 0, "Initial depth should be 0");
        assertEq(openPositionWrapper.settleCalls(), 0, "Initial settleCalls should be 0");
    }

    /// @notice Test parseWrapperData function
    function test_OpenPositionWrapper_ParseWrapperData() external view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user,
            account: address(uint160(user) ^ 1),
            deadline: block.timestamp + 1 hours,
            collateralVault: eSUSDS,
            borrowVault: eWETH,
            collateralAmount: SUSDS_MARGIN,
            borrowAmount: 1e18
        });

        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingData = openPositionWrapper.parseWrapperData(wrapperData);

        // After parsing OpenPositionParams, remaining data should be empty
        assertEq(remainingData.length, 0, "Remaining data should be empty");
    }

    /// @notice Test setting pre-approved hash
    function test_OpenPositionWrapper_SetPreApprovedHash() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user,
            account: address(uint160(user) ^ 1),
            deadline: block.timestamp + 1 hours,
            collateralVault: eSUSDS,
            borrowVault: eWETH,
            collateralAmount: SUSDS_MARGIN,
            borrowAmount: 1e18
        });

        bytes32 hash = openPositionWrapper.getApprovalHash(params);

        // Initially hash should not be approved
        assertEq(openPositionWrapper.preApprovedHashes(user, hash), 0, "Hash should not be approved initially");

        // User pre-approves the hash
        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit PreApprovedHashes.PreApprovedHash(user, hash, true);
        openPositionWrapper.setPreApprovedHash(hash, true);

        // Hash should now be approved
        assertGt(openPositionWrapper.preApprovedHashes(user, hash), 0, "Hash should be approved");

        // User revokes the approval
        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit PreApprovedHashes.PreApprovedHash(user, hash, false);
        openPositionWrapper.setPreApprovedHash(hash, false);

        // Hash should no longer be approved
        assertEq(openPositionWrapper.preApprovedHashes(user, hash), 0, "Hash should not be approved after revocation");
    }

    /// @notice Test opening a position with pre-approved hash (no signature needed)
    function test_OpenPositionWrapper_WithPreApprovedHash() external {
        vm.skip(bytes(FORK_RPC_URL).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 expectedBuyAmount = 999e18; // Expect to receive 999 eSUSDS

        address account = address(uint160(user) ^ 1);

        // Prepare OpenPositionParams
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user,
            account: account,
            deadline: block.timestamp + 1 hours,
            collateralVault: eSUSDS,
            borrowVault: eWETH,
            collateralAmount: SUSDS_MARGIN,
            borrowAmount: borrowAmount
        });

        // Get settlement data
        SettlementData memory settlement = getOpenPositionSettlement(
            user,
            account,
            WETH,
            eSUSDS,
            borrowAmount,
            expectedBuyAmount
        );

        vm.startPrank(user);

        // User approves SUSDS vault for deposit of the margin
        // This is only needed if the user is depositing new margin
        IERC20(SUSDS).approve(eSUSDS, type(uint256).max);

        // User approves the wrapper to be operator (both of the main account and the subaccount)
        // This is only needed if its the first time the user/account is using this wrapper
        evc.setAccountOperator(user, address(openPositionWrapper), true);
        evc.setAccountOperator(account, address(openPositionWrapper), true);

        // User pre-approves the hash for the wrapper operation (absolutely required every order)
        bytes32 hash = openPositionWrapper.getApprovalHash(params);
        openPositionWrapper.setPreApprovedHash(hash, true);

        // User pre-approves the order on CowSwap
        // NOTE: this could technically be exchanged for a Permit2 approve on the wrapper contract and EIP-1271 authentication,
        // and that would leave the user with only 1 off-chain Permit2 call
        // but combined with the approval txns that are needed above, this flow doesn't seem very viable.
        cowSettlement.setPreSignature(settlement.orderUid, true);

        vm.stopPrank();

        // Record balances before
        uint256 debtBefore = IEVault(eWETH).debtOf(account);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(CowSettlement.settle, (
            settlement.tokens,
            settlement.clearingPrices,
            settlement.trades,
            settlement.interactions
        ));

        // Encode wrapper data with OpenPositionParams (empty signature since pre-approved)
        bytes memory wrapperData = abi.encode(params, new bytes(0));

        // Execute wrapped settlement through solver
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(openPositionWrapper);
        datas[0] = abi.encodeCall(
            openPositionWrapper.wrappedSettle,
            (settleData, wrapperData)
        );

        solver.runBatch(targets, datas);

        // Verify the position was created successfully
        assertApproxEqAbs(
            IEVault(eSUSDS).convertToAssets(IERC20(eSUSDS).balanceOf(account)),
            expectedBuyAmount + SUSDS_MARGIN,
            1 ether,
            "User should have collateral deposited"
        );
        assertEq(
            IEVault(eWETH).debtOf(account),
            borrowAmount,
            "User should have debt"
        );
        assertEq(debtBefore, 0, "User should start with no debt");
    }
}
