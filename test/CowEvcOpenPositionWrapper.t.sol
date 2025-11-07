// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order, IERC20 as CowERC20} from "cow/libraries/GPv2Order.sol";

import {IEVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcOpenPositionWrapper} from "../src/CowEvcOpenPositionWrapper.sol";
import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {PreApprovedHashes} from "../src/PreApprovedHashes.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcOpenPositionWrapper
/// @notice Tests the full flow of opening a leveraged position using the new wrapper contract
contract CowEvcOpenPositionWrapperTest is CowBaseTest {
    CowEvcOpenPositionWrapper public openPositionWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant SUSDS_MARGIN = 2000e18;
    uint256 constant DEFAULT_BORROW_AMOUNT = 1e18;
    uint256 constant DEFAULT_BUY_AMOUNT = 999e18;

    function setUp() public override {
        super.setUp();

        // Deploy the new open position wrapper
        openPositionWrapper = new CowEvcOpenPositionWrapper(address(evc), COW_SETTLEMENT);

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(openPositionWrapper));
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
        ICowSettlement.Trade[] trades;
        ICowSettlement.Interaction[][3] interactions;
    }

    /// @notice Create default OpenPositionParams for testing
    function _createDefaultParams(address owner, address account)
        internal
        view
        returns (CowEvcOpenPositionWrapper.OpenPositionParams memory)
    {
        return CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: owner,
            account: account,
            deadline: block.timestamp + 1 hours,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: SUSDS_MARGIN,
            borrowAmount: DEFAULT_BORROW_AMOUNT
        });
    }

    /// @notice Setup user approvals for SUSDS deposit
    function _setupUserSusdsApproval() internal {
        vm.prank(user);
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);
    }

    /// @notice Setup user approvals for pre-approved hash flow
    function _setupUserPreApprovedFlow(address account, bytes32 hash) internal {
        vm.startPrank(user);
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);
        evc.setAccountOperator(user, address(openPositionWrapper), true);
        evc.setAccountOperator(account, address(openPositionWrapper), true);
        openPositionWrapper.setPreApprovedHash(hash, true);
        vm.stopPrank();
    }

    /// @notice Create permit signature for EVC operator
    function _createPermitSignature(CowEvcOpenPositionWrapper.OpenPositionParams memory params)
        internal
        returns (bytes memory)
    {
        ecdsa.setPrivateKey(privateKey);
        return ecdsa.signPermit(
            params.owner,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            params.deadline,
            0,
            openPositionWrapper.getSignedCalldata(params)
        );
    }

    /// @notice Encode wrapper data with length prefix
    function _encodeWrapperData(CowEvcOpenPositionWrapper.OpenPositionParams memory params, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory wrapperData = abi.encode(params, signature);
        return abi.encodePacked(uint16(wrapperData.length), wrapperData);
    }

    /// @notice Execute wrapped settlement through solver
    function _executeWrappedSettlement(bytes memory settleData, bytes memory wrapperData) internal {
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(openPositionWrapper);
        datas[0] = abi.encodeCall(openPositionWrapper.wrappedSettle, (settleData, wrapperData));
        solver.runBatch(targets, datas);
    }

    /// @notice Verify position was opened successfully
    function _verifyPositionOpened(
        address account,
        uint256 expectedCollateral,
        uint256 expectedDebt,
        uint256 allowedDelta
    ) internal view {
        assertApproxEqAbs(
            IEVault(ESUSDS).convertToAssets(IERC20(ESUSDS).balanceOf(account)),
            expectedCollateral,
            allowedDelta,
            "User should have collateral deposited"
        );
        assertEq(IEVault(EWETH).debtOf(account), expectedDebt, "User should have debt");
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
        r.trades = new ICowSettlement.Trade[](1);
        r.trades[0] = getTradeData(sellAmount, buyAmount, validTo, owner, r.orderData.receiver, false);

        // Get tokens and prices
        (r.tokens, r.clearingPrices) = getTokensAndPrices();

        // Setup interactions - swap WETH to SUSDS, deposit to vault, and skim
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](3),
            new ICowSettlement.Interaction[](0)
        ];
        r.interactions[1][0] = getSwapInteraction(sellToken, IERC4626(buyVaultToken).asset(), sellAmount);
        r.interactions[1][1] = getDepositInteraction(buyVaultToken, buyAmount + 1 ether);
        r.interactions[1][2] = getSkimInteraction();
    }

    /// @notice Test opening a leveraged position using the new wrapper
    function test_OpenPositionWrapper_Success() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        address account = address(uint160(user) ^ 1);

        // Create params using helper
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement =
            getOpenPositionSettlement(user, account, WETH, ESUSDS, DEFAULT_BORROW_AMOUNT, DEFAULT_BUY_AMOUNT);

        // Setup user approvals
        _setupUserSusdsApproval();

        // User signs order (using setPreSignature for testing)
        vm.prank(user);
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

        // Create permit signature
        bytes memory permitSignature = _createPermitSignature(params);

        // Record balances before
        uint256 susdsBalanceBefore = IERC20(ESUSDS).balanceOf(user);
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement and wrapper data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, permitSignature);

        // Expect event emission
        vm.expectEmit(true, true, true, true);
        emit CowEvcOpenPositionWrapper.CowEvcPositionOpened(
            params.owner,
            params.account,
            params.collateralVault,
            params.borrowVault,
            params.collateralAmount,
            params.borrowAmount
        );

        // Execute wrapped settlement
        _executeWrappedSettlement(settleData, wrapperData);

        // Verify position was created successfully
        _verifyPositionOpened(account, DEFAULT_BUY_AMOUNT + SUSDS_MARGIN, DEFAULT_BORROW_AMOUNT, 1 ether);
        assertEq(debtBefore, 0, "User should start with no debt");
        assertEq(susdsBalanceBefore, 0, "User should start with no eSUSDS");
    }

    /// @notice Test that unauthorized users cannot call evcInternalSettle directly
    function test_OpenPositionWrapper_UnauthorizedInternalSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call evcInternalSettle directly (not through EVC)
        vm.expectRevert(abi.encodeWithSelector(CowEvcOpenPositionWrapper.Unauthorized.selector, address(this)));
        openPositionWrapper.evcInternalSettle(settleData, wrapperData);
    }

    /// @notice Test that non-solvers cannot call wrappedSettle
    function test_OpenPositionWrapper_NonSolverCannotSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call wrappedSettle as non-solver
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, address(this)));
        openPositionWrapper.wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test parseWrapperData function
    function test_OpenPositionWrapper_ParseWrapperData() external view {
        address account = address(uint160(user) ^ 1);
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _createDefaultParams(user, account);

        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingData = openPositionWrapper.parseWrapperData(wrapperData);

        // After parsing OpenPositionParams, remaining data should be empty
        assertEq(remainingData.length, 0, "Remaining data should be empty");
    }

    /// @notice Test setting pre-approved hash
    function test_OpenPositionWrapper_SetPreApprovedHash() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        address account = address(uint160(user) ^ 1);
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _createDefaultParams(user, account);
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
        vm.skip(bytes(forkRpcUrl).length == 0);

        address account = address(uint160(user) ^ 1);

        // Create params using helper
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement =
            getOpenPositionSettlement(user, account, WETH, ESUSDS, DEFAULT_BORROW_AMOUNT, DEFAULT_BUY_AMOUNT);

        // Setup user approvals and pre-approve hash
        bytes32 hash = openPositionWrapper.getApprovalHash(params);
        _setupUserPreApprovedFlow(account, hash);

        // User pre-approves the order on CowSwap
        vm.prank(user);
        COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

        // Record balances before
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement and wrapper data (empty signature since pre-approved)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        // Expect event emission
        vm.expectEmit(true, true, true, true);
        emit CowEvcOpenPositionWrapper.CowEvcPositionOpened(
            params.owner,
            params.account,
            params.collateralVault,
            params.borrowVault,
            params.collateralAmount,
            params.borrowAmount
        );

        // Execute wrapped settlement
        _executeWrappedSettlement(settleData, wrapperData);

        // Verify the position was created successfully
        _verifyPositionOpened(account, DEFAULT_BUY_AMOUNT + SUSDS_MARGIN, DEFAULT_BORROW_AMOUNT, 1 ether);
        assertEq(debtBefore, 0, "User should start with no debt");
    }
}
