// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {IEVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcBaseWrapper} from "../src/CowEvcOpenPositionWrapper.sol";
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

    uint256 constant SUSDS_MARGIN = 5000e18;
    uint256 constant DEFAULT_BORROW_AMOUNT = 1e18;
    uint256 constant DEFAULT_BUY_AMOUNT = 2495e18;

    function setUp() public override {
        super.setUp();

        // Deploy the new open position wrapper
        openPositionWrapper = new CowEvcOpenPositionWrapper(address(EVC), COW_SETTLEMENT);

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(openPositionWrapper));
        vm.stopPrank();

        ecdsa = new SignerECDSA(EVC);

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
        EVC.setAccountOperator(user, address(openPositionWrapper), true);
        EVC.setAccountOperator(account, address(openPositionWrapper), true);
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
    ) public returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create trade and extract order data

        // Get tokens and prices
        (r.tokens, r.clearingPrices) = getTokensAndPrices();

        r.trades = new ICowSettlement.Trade[](1);
        (r.trades[0], r.orderData, r.orderUid) =
            setupCowOrder(r.tokens, 0, 1, sellAmount, buyAmount, validTo, owner, receiver, false);

        // Setup interactions - swap WETH to SUSDS, deposit to vault, and skim
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](3),
            new ICowSettlement.Interaction[](0)
        ];
        r.interactions[1][0] = getSwapInteraction(sellToken, IERC4626(buyVaultToken).asset(), sellAmount);
        r.interactions[1][1] = getDepositInteraction(buyVaultToken, buyAmount + 1 ether);
        r.interactions[1][2] = getSkimInteraction(buyVaultToken);
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

        // User signs order
        // Does not need to run here because its done in `setupCowOrder`

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
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, permitSignature));

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
        executeWrappedSettlement(address(openPositionWrapper), settleData, wrapperData);

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
        vm.expectRevert(abi.encodeWithSelector(CowEvcBaseWrapper.Unauthorized.selector, address(this)));
        openPositionWrapper.evcInternalSettle(settleData, hex"", wrapperData);
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
        // Does not need to run here because its executed in `setupCowOrder`

        // Record balances before
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement and wrapper data (empty signature since pre-approved)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, new bytes(0)));

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
        executeWrappedSettlement(address(openPositionWrapper), settleData, wrapperData);

        // Verify the position was created successfully
        _verifyPositionOpened(account, DEFAULT_BUY_AMOUNT + SUSDS_MARGIN, DEFAULT_BORROW_AMOUNT, 1 ether);
        assertEq(debtBefore, 0, "User should start with no debt");
    }

    /// @notice Test that the wrapper can handle being called three times in the same chain
    /// @dev Two users open positions in the same direction (long SUSDS), one user opens opposite (long WETH)
    function test_OpenPositionWrapper_ThreeUsers_TwoSameOneOpposite() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Configure vault LTVs for both directions
        // Already configured: eSUSDS collateral -> eWETH borrow
        // Need to configure: eWETH collateral -> eSUSDS borrow
        vm.startPrank(IEVault(ESUSDS).governorAdmin());
        IEVault(ESUSDS).setLTV(EWETH, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup User1: Has SUSDS, will borrow WETH and swap WETH→SUSDS (long SUSDS). Around 1 ETH
        address account1 = address(uint160(user) ^ 1);
        deal(SUSDS, user, 1000 ether);

        // Approve SUSDS spending by eSUSDS for user1
        vm.startPrank(user);
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);

        // Approve WETH for COW Protocol for user1
        IERC20(WETH).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Setup User2: Has SUSDS, will borrow WETH and swap WETH→SUSDS. 3x the size (long SUSDS, same direction as user1). Around 3 ETH
        address account2 = address(uint160(user2) ^ 1);
        deal(SUSDS, user2, 1000 ether);

        // Approve SUSDS spending by eSUSDS for user2
        vm.startPrank(user2);
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);

        // Approve WETH for COW Protocol for user2
        IERC20(WETH).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Setup User3: Has WETH, will borrow SUSDS and swap SUSDS→WETH (long WETH, opposite direction). Around $5000
        address account3 = address(uint160(user3) ^ 1);
        deal(WETH, user3, 1 ether);

        // Approve WETH spending by eWETH for user2
        vm.startPrank(user3);
        IERC20(WETH).approve(EWETH, type(uint256).max);

        // Approve SUSDS for COW Protocol for user3
        IERC20(SUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Create params for User1: Deposit SUSDS, borrow WETH
        CowEvcOpenPositionWrapper.OpenPositionParams memory params1 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user,
            account: account1,
            deadline: block.timestamp + 1 hours,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: 1000 ether,
            borrowAmount: 1 ether
        });

        // Create params for User2: Deposit SUSDS, borrow WETH (same direction as User1)
        CowEvcOpenPositionWrapper.OpenPositionParams memory params2 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user2,
            account: account2,
            deadline: block.timestamp + 1 hours,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: 1000 ether,
            borrowAmount: 3 ether
        });

        CowEvcOpenPositionWrapper.OpenPositionParams memory params3 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user3,
            account: account3,
            deadline: block.timestamp + 1 hours,
            collateralVault: EWETH,
            borrowVault: ESUSDS,
            collateralAmount: 1 ether,
            borrowAmount: 5000 ether
        });

        // Create permit signatures for all users
        ecdsa.setPrivateKey(privateKey);
        bytes memory permitSignature1 = ecdsa.signPermit(
            params1.owner,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            params1.deadline,
            0,
            openPositionWrapper.getSignedCalldata(params1)
        );

        ecdsa.setPrivateKey(privateKey2);
        bytes memory permitSignature2 = ecdsa.signPermit(
            params2.owner,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            params2.deadline,
            0,
            openPositionWrapper.getSignedCalldata(params2)
        );

        ecdsa.setPrivateKey(privateKey3);
        bytes memory permitSignature3 = ecdsa.signPermit(
            params3.owner,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            params3.deadline,
            0,
            openPositionWrapper.getSignedCalldata(params3)
        );

        // Create settlement with all three trades
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Setup tokens array: WETH, eSUSDS, SUSDS, eWETH
        address[] memory tokens = new address[](4);
        tokens[0] = SUSDS;
        tokens[1] = WETH;
        tokens[2] = ESUSDS;
        tokens[3] = EWETH;

        uint256[] memory clearingPrices = new uint256[](4);
        clearingPrices[0] = 1 ether; // SUSDS price
        clearingPrices[1] = 2500 ether; // WETH price
        clearingPrices[2] = 0.99 ether; // eSUSDS price
        clearingPrices[3] = 2495 ether; // eWETH price

        // Create trades and extract orders
        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](3);

        // Trade 1: User1 sells WETH for eSUSDS
        (trades[0],,) = setupCowOrder(tokens, 1, 2, params1.borrowAmount, 0, validTo, user, account1, false);

        // Trade 2: User2 sells WETH for eSUSDS (same direction as User1)
        (trades[1],,) = setupCowOrder(tokens, 1, 2, params2.borrowAmount, 0, validTo, user2, account2, false);

        // Trade 3: User3 sells SUSDS for eWETH (opposite direction)
        (trades[2],,) = setupCowOrder(tokens, 0, 3, params3.borrowAmount, 0, validTo, user3, account3, false);

        // Setup interactions to handle the swaps and deposits
        ICowSettlement.Interaction[][3] memory interactions;
        interactions[0] = new ICowSettlement.Interaction[](0);
        interactions[1] = new ICowSettlement.Interaction[](5);
        interactions[2] = new ICowSettlement.Interaction[](0);

        // Trade 1 & 2: coincidence of wants: WETH → SUSDS for the difference in all the users trades (2 WETH total difference)
        interactions[1][0] = getSwapInteraction(WETH, SUSDS, 2 ether);
        // Deposit SUSDS to eSUSDS vault for both user1 and user2
        interactions[1][1] = getDepositInteraction(ESUSDS, 10000 ether);
        // Deposit WETH to eWETH vault
        interactions[1][2] = getDepositInteraction(EWETH, 2 ether);

        // Skim eSUSDS vault
        interactions[1][3] = getSkimInteraction(ESUSDS);
        // Skim eWETH vault
        interactions[1][4] = getSkimInteraction(EWETH);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(ICowSettlement.settle, (tokens, clearingPrices, trades, interactions));

        // Chain wrapper data: wrapper(user1) → wrapper(user2) → wrapper(user3) → settlement
        // Format: [2-byte len][wrapper1 data][next wrapper address][2-byte len][wrapper2 data][next wrapper address][2-byte len][wrapper3 data]
        bytes memory wrapper1Data = abi.encode(params1, permitSignature1);
        bytes memory wrapper2Data = abi.encode(params2, permitSignature2);
        bytes memory wrapper3Data = abi.encode(params3, permitSignature3);

        bytes memory wrapperData = abi.encodePacked(
            uint16(wrapper1Data.length),
            wrapper1Data,
            address(openPositionWrapper),
            uint16(wrapper2Data.length),
            wrapper2Data,
            address(openPositionWrapper),
            uint16(wrapper3Data.length),
            wrapper3Data
        );

        // Execute wrapped settlement through solver
        // Note: We don't use expectEmit here because there are many Transfer events
        // from the complex multi-user settlement that interfere with strict event matching
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(openPositionWrapper);
        datas[0] = abi.encodeCall(openPositionWrapper.wrappedSettle, (settleData, wrapperData));
        solver.runBatch(targets, datas);

        // Verify all three positions were opened successfully
        // User1: Should have SUSDS collateral and WETH debt
        _verifyPositionOpened(account1, 1000 ether + 2500 ether, 1 ether, 100 ether);

        // User2: Should have SUSDS collateral and WETH debt (same as User1)
        _verifyPositionOpened(account2, 1000 ether + 7500 ether, 3 ether, 100 ether);

        // User3: Should have WETH collateral and SUSDS debt
        assertApproxEqAbs(
            IEVault(EWETH).convertToAssets(IERC20(EWETH).balanceOf(account3)),
            1 ether + 2 ether,
            0.2 ether,
            "User3 should have WETH collateral deposited"
        );
        assertEq(IEVault(ESUSDS).debtOf(account3), 5000 ether, "User3 should have SUSDS debt");
    }
}
