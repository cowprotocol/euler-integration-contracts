// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcClosePositionWrapper} from "../src/CowEvcClosePositionWrapper.sol";
import {CowEvcBaseWrapper} from "../src/CowEvcBaseWrapper.sol";
import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {PreApprovedHashes} from "../src/PreApprovedHashes.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcClosePositionWrapper
/// @notice Tests the full flow of closing a leveraged position using the new wrapper contract
contract CowEvcClosePositionWrapperTest is CowBaseTest {
    CowEvcClosePositionWrapper public closePositionWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant USDS_MARGIN = 3000e18;
    uint256 constant DEFAULT_SELL_AMOUNT = 2510 ether;
    uint256 constant DEFAULT_BUY_AMOUNT = 1.001 ether;

    function setUp() public override {
        super.setUp();

        // Deploy the new close position wrapper
        closePositionWrapper = new CowEvcClosePositionWrapper(address(EVC), COW_SETTLEMENT);

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(closePositionWrapper));
        vm.stopPrank();

        ecdsa = new SignerECDSA(EVC);

        // Setup user with USDS
        deal(USDS, user, 10000e18);
    }

    struct SettlementData {
        bytes orderUid;
        GPv2Order.Data orderData;
        address[] tokens;
        uint256[] clearingPrices;
        ICowSettlement.Trade[] trades;
        ICowSettlement.Interaction[][3] interactions;
    }

    /// @notice Create default ClosePositionParams for testing
    function _createDefaultParams(address owner, address account)
        internal
        view
        returns (CowEvcClosePositionWrapper.ClosePositionParams memory)
    {
        return CowEvcClosePositionWrapper.ClosePositionParams({
            owner: owner,
            account: account,
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: EUSDS,
            collateralAmount: DEFAULT_SELL_AMOUNT,
            repayAmount: DEFAULT_BUY_AMOUNT,
            kind: GPv2Order.KIND_BUY
        });
    }

    /// @notice Setup pre-approved hash flow for close position
    function _setupPreApprovedFlow(address account, bytes32 hash) internal {
        vm.startPrank(user);

        // Set operators
        EVC.setAccountOperator(user, address(closePositionWrapper), true);
        EVC.setAccountOperator(account, address(closePositionWrapper), true);

        // Pre-approve hash
        closePositionWrapper.setPreApprovedHash(hash, true);

        // Approve vault shares from subaccount
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: account,
            targetContract: EUSDS,
            value: 0,
            data: abi.encodeCall(IERC20.approve, (address(closePositionWrapper), type(uint256).max))
        });
        EVC.batch(items);

        // Approve the wrapper to send excess tokens back to the subaccount they came from
        IEVault(EUSDS).approve(address(closePositionWrapper), type(uint256).max);

        // Approve vault shares for settlement
        IEVault(EUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // Approve wrapper to spend WETH for repayment
        IERC20(WETH).approve(address(closePositionWrapper), type(uint256).max);

        vm.stopPrank();
    }

    /// @notice Setup approvals for a specific user to close their position
    function _setupClosePositionApprovalsFor(
        address owner,
        address account,
        address collateralVault,
        address repaymentAsset
    ) internal {
        vm.startPrank(owner);

        // Approve vault shares from subaccount
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: account,
            targetContract: collateralVault,
            value: 0,
            data: abi.encodeCall(IERC20.approve, (address(closePositionWrapper), type(uint256).max))
        });
        EVC.batch(items);

        // Approve transfer of any remaining vault shares from the wrapper back to the subaccount
        IEVault(collateralVault).approve(address(closePositionWrapper), type(uint256).max);

        // Approve vault shares for settlement
        IEVault(collateralVault).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // Approve wrapper to spend repayment asset
        IERC20(repaymentAsset).approve(address(closePositionWrapper), type(uint256).max);

        vm.stopPrank();
    }

    /// @notice Create permit signature for any user
    function _createPermitSignatureFor(
        CowEvcClosePositionWrapper.ClosePositionParams memory params,
        uint256 userPrivateKey
    ) internal returns (bytes memory) {
        ecdsa.setPrivateKey(userPrivateKey);
        return ecdsa.signPermit(
            params.owner,
            address(closePositionWrapper),
            uint256(uint160(address(closePositionWrapper))),
            0,
            params.deadline,
            0,
            closePositionWrapper.encodePermitData(params)
        );
    }

    /// @notice Create settlement data for closing a leveraged position. It will always sell EUSDS to buy WETH
    /// @dev Sells vault shares to buy repayment token (WETH)
    function getClosePositionSettlement(address owner, address receiver, uint256 sellAmount, uint256 buyAmount)
        public
        returns (SettlementData memory r)
    {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Get tokens and prices
        (r.tokens, r.clearingPrices) = getTokensAndPrices();

        // Get trade data
        r.trades = new ICowSettlement.Trade[](1);
        (r.trades[0], r.orderData, r.orderUid) = setupCowOrder({
            tokens: r.tokens,
            sellTokenIndex: 2,
            buyTokenIndex: 1,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            owner: owner,
            receiver: receiver,
            isBuy: true
        });

        // Setup interactions - withdraw from vault, swap to repayment token
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](2),
            new ICowSettlement.Interaction[](0)
        ];
        r.interactions[1][0] = getWithdrawInteraction(EUSDS, buyAmount * r.clearingPrices[1] / 1e18);
        r.interactions[1][1] = getSwapInteraction(IERC4626(EUSDS).asset(), WETH, buyAmount * r.clearingPrices[1] / 1e18);
    }

    /// @notice Test closing a leveraged position using the wrapper
    function test_ClosePositionWrapper_SuccessFullRepay() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Verify position exists
        uint256 debtBefore = IEVault(EWETH).debtOf(account);
        assertEq(debtBefore, borrowAmount, "Position should have debt");

        // Create params using helper
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = getClosePositionSettlement({
            owner: user, receiver: user, sellAmount: DEFAULT_SELL_AMOUNT, buyAmount: DEFAULT_BUY_AMOUNT
        });

        // User signs order (already done in setupCowOrder)

        // Setup approvals
        _setupClosePositionApprovalsFor(user, account, EUSDS, WETH);

        // Create permit signature
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // Record balances before closing
        uint256 collateralBefore = IERC20(EUSDS).balanceOf(user);
        uint256 collateralBeforeAccount = IERC20(EUSDS).balanceOf(account);

        // Encode settlement and wrapper data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, permitSignature));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcClosePositionWrapper.CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            params.repayAmount,
            params.kind
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");
        assertLt(
            IERC20(EUSDS).balanceOf(account), collateralBeforeAccount, "User should have less collateral after closing"
        );
        assertEq(IERC20(EUSDS).balanceOf(user), collateralBefore, "User main account balance should not have changed");
        assertGt(IERC20(EUSDS).balanceOf(account), 0, "User should have some collateral remaining");
    }

    /// @notice Test that unauthorized users cannot call evcInternalSettle directly
    function test_ClosePositionWrapper_UnauthorizedInternalSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call evcInternalSettle directly (not through EVC)
        vm.expectRevert(abi.encodeWithSelector(CowEvcBaseWrapper.Unauthorized.selector, address(this)));
        closePositionWrapper.evcInternalSettle(settleData, wrapperData, wrapperData);
    }

    /// @notice Test that non-solvers cannot call wrappedSettle
    function test_ClosePositionWrapper_NonSolverCannotSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        // Try to call wrappedSettle as non-solver
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, user));
        closePositionWrapper.wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test shrinking the position with partial repayment
    function test_ClosePositionWrapper_PartialRepay() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 2e18;
        uint256 collateralAmount = USDS_MARGIN + 4990e18;
        uint256 sellAmount = 2500e18;
        uint256 buyAmount = 0.98e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params with custom amounts and KIND_SELL
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);
        params.collateralAmount = sellAmount;
        params.repayAmount = buyAmount;
        params.kind = GPv2Order.KIND_SELL;

        // Get settlement data
        SettlementData memory settlement =
            getClosePositionSettlement({owner: user, receiver: user, sellAmount: sellAmount, buyAmount: buyAmount});

        // User signs order (already done in setupCowOrder)

        // Setup approvals
        _setupClosePositionApprovalsFor(user, account, EUSDS, WETH);

        // Create permit signature
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // Encode settlement and wrapper data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, permitSignature));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcClosePositionWrapper.CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            params.repayAmount,
            params.kind
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify partial repayment
        uint256 debtAfter = IEVault(EWETH).debtOf(account);
        assertApproxEqAbs(debtAfter, borrowAmount - buyAmount, 0.01e18, "Debt should be reduced by repaid amount");
        assertEq(IERC20(WETH).balanceOf(user), 0, "User should have used any collateral they received to repay");
    }

    /// @notice Test parseWrapperData function
    function test_ClosePositionWrapper_ParseWrapperData() external view {
        address account = address(uint160(user) ^ uint8(0x01));
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);
        params.collateralAmount = 0;
        params.repayAmount = type(uint256).max;

        bytes memory wrapperData = abi.encode(params, new bytes(65));

        // Should not revert for valid wrapper data
        closePositionWrapper.validateWrapperData(wrapperData);
    }

    /// @notice Test setting pre-approved hash
    function test_ClosePositionWrapper_SetPreApprovedHash() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        address account = address(uint160(user) ^ uint8(0x01));
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);
        params.collateralAmount = 0;
        params.repayAmount = type(uint256).max;

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
        assertEq(
            closePositionWrapper.preApprovedHashes(user, hash),
            uint256(keccak256("PreApprovedHashes.Consumed")),
            "Hash should not be approved after revocation"
        );
    }

    /// @notice Test closing a position with pre-approved hash (no signature needed)
    function test_ClosePositionWrapper_WithPreApprovedHash() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params using helper
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = getClosePositionSettlement({
            owner: user, receiver: user, sellAmount: DEFAULT_SELL_AMOUNT, buyAmount: DEFAULT_BUY_AMOUNT
        });

        // Setup pre-approved flow
        bytes32 hash = closePositionWrapper.getApprovalHash(params);
        _setupPreApprovedFlow(account, hash);

        // User signs order (already done in setupCowOrder)

        // Record balances before closing
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement and wrapper data (empty signature since pre-approved)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, new bytes(0)));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcClosePositionWrapper.CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            params.repayAmount,
            params.kind
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");
        assertEq(debtBefore, borrowAmount, "User should have started with debt");
    }

    /// @notice Test that invalid signature causes the transaction to revert
    function test_ClosePositionWrapper_InvalidSignatureReverts() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ 1);

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params using helper
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = getClosePositionSettlement({
            owner: user, receiver: user, sellAmount: DEFAULT_SELL_AMOUNT, buyAmount: DEFAULT_BUY_AMOUNT
        });

        // Setup approvals
        _setupClosePositionApprovalsFor(user, account, EUSDS, WETH);

        // Create INVALID permit signature by signing with wrong private key (user2's key instead of user's)
        ecdsa.setPrivateKey(privateKey2); // Wrong private key!
        bytes memory invalidPermitSignature = ecdsa.signPermit(
            params.owner,
            address(closePositionWrapper),
            uint256(uint160(address(closePositionWrapper))),
            0,
            params.deadline,
            0,
            closePositionWrapper.encodePermitData(params)
        );

        // Encode settlement and wrapper data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, invalidPermitSignature));

        // Execute wrapped settlement - should revert with EVC_NotAuthorized due to invalid signature
        vm.expectRevert(abi.encodeWithSignature("EVC_NotAuthorized()"));
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test that the wrapper can handle being called three times in the same chain
    /// @dev Two users close positions in the same direction (long USDS), one user closes opposite (long WETH)
    function test_ClosePositionWrapper_ThreeUsers_TwoSameOneOpposite() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Configure vault LTVs for both directions
        vm.startPrank(IEVault(EUSDS).governorAdmin());
        IEVault(EUSDS).setLTV(EWETH, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup accounts
        address account1 = address(uint160(user) ^ 1);
        address account2 = address(uint160(user2) ^ 1);
        address account3 = address(uint160(user3) ^ 1);

        vm.label(user, "user");
        vm.label(user2, "user2");
        vm.label(user3, "user3");
        vm.label(account1, "account1");
        vm.label(account2, "account2");
        vm.label(account3, "account3");

        // Setup User1: Long USDS (USDS collateral, WETH debt). ~1 ETH debt
        setupLeveragedPositionFor({
            owner: user,
            account: account1,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 5500 ether,
            borrowAmount: 1 ether
        });

        // Setup User2: Long USDS (USDS collateral, WETH debt). ~3 ETH debt
        setupLeveragedPositionFor({
            owner: user2,
            account: account2,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 12000 ether,
            borrowAmount: 3 ether
        });

        // Setup User3: Long WETH (WETH collateral, USDS debt). ~5000 USDS debt
        setupLeveragedPositionFor({
            owner: user3,
            account: account3,
            collateralVault: EWETH,
            borrowVault: EUSDS,
            collateralAmount: 3 ether,
            borrowAmount: 5000 ether
        });

        // Verify positions exist
        assertEq(IEVault(EWETH).debtOf(account1), 1 ether, "User1 should have WETH debt");
        assertEq(IEVault(EWETH).debtOf(account2), 3 ether, "User2 should have WETH debt");
        assertEq(IEVault(EUSDS).debtOf(account3), 5000 ether, "User3 should have USDS debt");

        // confirm the amounts before repayment
        assertApproxEqAbs(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account1)),
            5500 ether,
            1 ether,
            "User1 should have some EUSDS collateral before closing"
        );
        assertApproxEqAbs(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account2)),
            12000 ether,
            1 ether,
            "User2 should have some EUSDS collateral before closing"
        );
        assertApproxEqAbs(
            IERC4626(EWETH).convertToAssets(IEVault(EWETH).balanceOf(account3)),
            3 ether,
            0.01 ether,
            "User3 should have some EWETH collateral before closing"
        );

        // Setup approvals for all users
        _setupClosePositionApprovalsFor(user, account1, EUSDS, WETH);
        _setupClosePositionApprovalsFor(user2, account2, EUSDS, WETH);
        _setupClosePositionApprovalsFor(user3, account3, EWETH, USDS);

        // Create params for all users
        CowEvcClosePositionWrapper.ClosePositionParams memory params1 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account1,
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: EUSDS,
            collateralAmount: 2550 ether,
            repayAmount: 1.001 ether,
            kind: GPv2Order.KIND_BUY
        });

        CowEvcClosePositionWrapper.ClosePositionParams memory params2 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user2,
            account: account2,
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: EUSDS,
            collateralAmount: 7600 ether,
            repayAmount: 3.003 ether,
            kind: GPv2Order.KIND_BUY
        });

        CowEvcClosePositionWrapper.ClosePositionParams memory params3 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user3,
            account: account3,
            deadline: block.timestamp + 1 hours,
            borrowVault: EUSDS,
            collateralVault: EWETH,
            collateralAmount: 2.1 ether,
            repayAmount: 5005 ether,
            kind: GPv2Order.KIND_BUY
        });

        // Create permit signatures for all users
        bytes memory permitSignature1 = _createPermitSignatureFor(params1, privateKey);
        bytes memory permitSignature2 = _createPermitSignatureFor(params2, privateKey2);
        bytes memory permitSignature3 = _createPermitSignatureFor(params3, privateKey3);

        // Create settlement with all three trades
        uint32 validTo = uint32(block.timestamp + 1 hours);

        (address[] memory tokens, uint256[] memory clearingPrices) = getTokensAndPrices();

        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](3);
        (trades[0],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 2,
            buyTokenIndex: 1,
            sellAmount: params1.collateralAmount,
            buyAmount: params1.repayAmount,
            validTo: validTo,
            owner: user,
            receiver: user,
            isBuy: true
        });
        (trades[1],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 2,
            buyTokenIndex: 1,
            sellAmount: params2.collateralAmount,
            buyAmount: params2.repayAmount,
            validTo: validTo,
            owner: user2,
            receiver: user2,
            isBuy: true
        });
        (trades[2],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 3,
            buyTokenIndex: 0,
            sellAmount: params3.collateralAmount,
            buyAmount: params3.repayAmount,
            validTo: validTo,
            owner: user3,
            receiver: user3,
            isBuy: true
        });

        // Setup interactions
        ICowSettlement.Interaction[][3] memory interactions;
        interactions[0] = new ICowSettlement.Interaction[](0);
        interactions[1] = new ICowSettlement.Interaction[](3);
        interactions[2] = new ICowSettlement.Interaction[](0);

        // We pull the money out of the euler vaults
        interactions[1][0] = getWithdrawInteraction(
            EUSDS, (params1.repayAmount + params2.repayAmount) * clearingPrices[1] / clearingPrices[0]
        );
        interactions[1][1] = getWithdrawInteraction(EWETH, params3.repayAmount * clearingPrices[0] / clearingPrices[1]);

        // We swap. We only need to swap the difference of the 3 closes (since coincidence of wants)
        // It comes out to 5000 USDS needs to become WETH
        interactions[1][2] = getSwapInteraction(USDS, WETH, 5000 ether);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(ICowSettlement.settle, (tokens, clearingPrices, trades, interactions));

        // Chain wrapper data
        bytes memory wrapper1Data = abi.encode(params1, permitSignature1);
        bytes memory wrapper2Data = abi.encode(params2, permitSignature2);
        bytes memory wrapper3Data = abi.encode(params3, permitSignature3);

        bytes memory wrapperData = abi.encodePacked(
            uint16(wrapper1Data.length),
            wrapper1Data,
            address(closePositionWrapper),
            uint16(wrapper2Data.length),
            wrapper2Data,
            address(closePositionWrapper),
            uint16(wrapper3Data.length),
            wrapper3Data
        );

        // Execute wrapped settlement
        closePositionWrapper.wrappedSettle(settleData, wrapperData);

        // Verify all positions closed successfully
        assertEq(IEVault(EWETH).debtOf(account1), 0, "User1 should have no WETH debt after closing");
        assertEq(IEVault(EWETH).debtOf(account2), 0, "User2 should have no WETH debt after closing");
        assertEq(IEVault(EUSDS).debtOf(account3), 0, "User3 should have no USDS debt after closing");

        // confirm the amounts after repayment
        assertApproxEqAbs(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account1)),
            5500 ether - 2502.5 ether,
            1 ether,
            "User1 should have some EUSDS collateral after closing"
        );
        assertApproxEqAbs(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account2)),
            12000 ether - 7507.5 ether,
            1 ether,
            "User2 should have some EUSDS collateral after closing"
        );
        assertApproxEqAbs(
            IERC4626(EWETH).convertToAssets(IEVault(EWETH).balanceOf(account3)),
            3 ether - 2 ether,
            0.01 ether,
            "User3 should have some EWETH collateral after closing"
        );
    }

    /// @notice Test that a malicious solver cannot use a postInteraction with EVC.permit to pull funds from an unauthorized user
    /// @dev Verifies that even with an attacker's permit signature, calling helperRepay with a different owner fails
    function test_ClosePositionWrapper_PostInteractionWithPermitUnauthorizedOwner() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ uint8(0x01));
        address attacker = user2;
        address attackerAccount = address(uint160(attacker) ^ uint8(0x01));

        vm.label(user, "Victim");
        vm.label(account, "Victim Account");
        vm.label(attackerAccount, "Attacker Account");
        vm.label(attacker, "Attacker");

        // Setup a leveraged position for user (legit position)
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Setup a leveraged position for the attacker
        uint256 attackerBorrowAmount = 1e18;
        uint256 attackerCollateralAmount = USDS_MARGIN + 2495e18;
        setupLeveragedPositionFor({
            owner: attacker,
            account: attackerAccount,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: attackerCollateralAmount,
            borrowAmount: attackerBorrowAmount
        });

        // Create normal close params for legitimate user
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(attacker, attackerAccount);

        // Get settlement data for the legitimate position close
        SettlementData memory settlement = getClosePositionSettlement({
            owner: attacker,
            receiver: attacker,
            sellAmount: attackerCollateralAmount / 2,
            buyAmount: attackerBorrowAmount / 2
        });

        // Setup normal approvals for user who is preparing to close their position
        _setupClosePositionApprovalsFor(user, account, EUSDS, WETH);

        // Setup approvals for the attacker
        _setupClosePositionApprovalsFor(attacker, attackerAccount, EUSDS, WETH);

        // Give the attacker extra WETH
        deal(WETH, attacker, 10e18);
        deal(EUSDS, attacker, 10e18);

        // Create permit signature from user
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // The attacker (as a malicious solver) tries to craft a postInteraction
        // that uses EVC.permit to authorize calling helperRepay with the attacker's account
        // instead of the legitimate user's account. This would attempt to pull funds from
        // the attacker's account without proper authorization context.

        // Create the malicious call to helperRepay with attacker's account
        IEVC.BatchItem[] memory maliciousBatch = new IEVC.BatchItem[](1);
        maliciousBatch[0] = IEVC.BatchItem({
            onBehalfOfAccount: attackerAccount,
            targetContract: address(closePositionWrapper),
            value: 0,
            data: abi.encodeCall(closePositionWrapper.helperRepay, (EWETH, user, attackerAccount))
        });

        vm.expectRevert(
            abi.encodeWithSelector(CowEvcBaseWrapper.SubaccountMustBeControlledByOwner.selector, attackerAccount, user)
        );
        vm.prank(attacker);
        EVC.batch(maliciousBatch);

        //bytes memory maliciousBatchCall = abi.encodeCall(EVC.batch, (maliciousBatch));

        // Create an EVC.permit call signed by the attacker
        // This permit would authorize the wrapper to call itself with the attacker's parameters
        ecdsa.setPrivateKey(privateKey2); // Use attacker's private key
        /*bytes memory permitSignatureFromAttacker = ecdsa.signPermit(
            attacker, // signer
            address(COW_SETTLEMENT), // sender (the attacker is authorizing this)
            uint256(uint160(address(closePositionWrapper))), // nonceNamespace
            1, // nonce
            block.timestamp + 1 hours, // deadline
            0, // value
            maliciousBatchCall // data
        );

        vm.expectRevert();
        EVC.permit(
            attacker, // signer
            address(COW_SETTLEMENT), // sender
            uint256(uint160(address(closePositionWrapper))), // nonceNamespace
            1, // nonce (+1 because we already consumed the first nonce)
            block.timestamp + 1 hours, // deadline
            0, // value
            maliciousBatchCall, // data
            permitSignatureFromAttacker // signature
        );*/

        // Create the postInteraction that calls EVC.permit
        /*ICowSettlement.Interaction memory maliciousPostInteraction = ICowSettlement.Interaction({
            target: address(EVC),
            value: 0,
            callData: abi.encodeCall(
                EVC.permit,
                (
                    attacker, // signer
                    address(COW_SETTLEMENT), // sender
                    uint256(uint160(address(closePositionWrapper))), // nonceNamespace
                    1, // nonce (+1 because we already consumed the first nonce)
                    block.timestamp + 1 hours, // deadline
                    0, // value
                    maliciousBatchCall, // data
                    permitSignatureFromAttacker // signature
                )
            )
        });

        // Create modified interactions with the malicious postInteraction
        ICowSettlement.Interaction[][3] memory modifiedInteractions;
        modifiedInteractions[0] = settlement.interactions[0]; // preInteractions (empty)
        modifiedInteractions[1] = settlement.interactions[1]; // intraInteractions
        modifiedInteractions[2] = new ICowSettlement.Interaction[](1);
        modifiedInteractions[2][0] = maliciousPostInteraction;

        // Re-encode settlement data with modified interactions containing the malicious permit
        bytes memory maliciousSettleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, modifiedInteractions)
        );

        bytes memory wrapperData = encodeWrapperData(abi.encode(params, permitSignature));

        // The transaction should revert because even though the attacker has signed a permit,
        // the helperRepay function tries to pull funds from the attacker's account.
        // The function checks that onBehalfOfAccount matches the account parameter,
        // but since this is being called in a postInteraction context, the EVC batch
        // is still operating on behalf of the original account, not the attacker.
        // This causes an authorization mismatch or transfer failure.
        vm.expectRevert();
        CowWrapper(address(closePositionWrapper)).wrappedSettle(maliciousSettleData, wrapperData);*/
    }
}
