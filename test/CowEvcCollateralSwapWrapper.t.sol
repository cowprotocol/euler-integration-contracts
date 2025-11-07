// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order, IERC20 as CowERC20} from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcCollateralSwapWrapper} from "../src/CowEvcCollateralSwapWrapper.sol";
import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcCollateralSwapWrapper
/// @notice Tests the full flow of swapping collateral between vaults
contract CowEvcCollateralSwapWrapperTest is CowBaseTest {
    CowEvcCollateralSwapWrapper public collateralSwapWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant SUSDS_MARGIN = 2000e18;
    uint256 constant DEFAULT_SWAP_AMOUNT = 500e18;
    uint256 constant DEFAULT_BUY_AMOUNT = 0.0045e8;

    function setUp() public override {
        super.setUp();

        // Deploy the collateral swap wrapper
        collateralSwapWrapper = new CowEvcCollateralSwapWrapper(address(EVC), COW_SETTLEMENT);

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(collateralSwapWrapper));
        vm.stopPrank();

        ecdsa = new SignerECDSA(EVC);

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
        EVC.enableCollateral(account, ESUSDS);
        EVC.enableController(account, EWETH);

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
        ICowSettlement.Trade[] trades;
        ICowSettlement.Interaction[][3] interactions;
    }

    /// @notice Create default CollateralSwapParams for testing
    function _createDefaultParams(address owner, address account)
        internal
        view
        returns (CowEvcCollateralSwapWrapper.CollateralSwapParams memory)
    {
        return CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: owner,
            account: account,
            deadline: block.timestamp + 1 hours,
            fromVault: ESUSDS,
            toVault: EWBTC,
            swapAmount: DEFAULT_SWAP_AMOUNT,
            kind: GPv2Order.KIND_SELL
        });
    }

    /// @notice Create permit signature for EVC operator
    function _createPermitSignature(CowEvcCollateralSwapWrapper.CollateralSwapParams memory params)
        internal
        returns (bytes memory)
    {
        ecdsa.setPrivateKey(privateKey);
        return ecdsa.signPermit(
            params.owner,
            address(collateralSwapWrapper),
            uint256(uint160(address(collateralSwapWrapper))),
            0,
            params.deadline,
            0,
            collateralSwapWrapper.getSignedCalldata(params)
        );
    }

    /// @notice Encode wrapper data with length prefix
    function _encodeWrapperData(CowEvcCollateralSwapWrapper.CollateralSwapParams memory params, bytes memory signature)
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
        targets[0] = address(collateralSwapWrapper);
        datas[0] = abi.encodeCall(collateralSwapWrapper.wrappedSettle, (settleData, wrapperData));
        solver.runBatch(targets, datas);
    }

    /// @notice Setup user approvals for collateral swap on subaccount
    function _setupSubaccountApprovals(address account, CowEvcCollateralSwapWrapper.CollateralSwapParams memory params)
        internal
    {
        vm.startPrank(user);

        // Approve vault shares from main account for settlement
        IEVault(params.fromVault).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // Approve transfer of vault shares from the subaccount to wrapper
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: account,
            targetContract: params.fromVault,
            value: 0,
            data: abi.encodeCall(IERC20.approve, (address(collateralSwapWrapper), type(uint256).max))
        });
        EVC.batch(items);

        // Set wrapper as operator for the subaccount
        EVC.setAccountOperator(account, address(collateralSwapWrapper), true);

        // Pre-approve the operation hash
        bytes32 hash = collateralSwapWrapper.getApprovalHash(params);
        collateralSwapWrapper.setPreApprovedHash(hash, true);

        vm.stopPrank();
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
    ) public returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Get tokens and prices
        r.tokens = new address[](2);
        r.tokens[0] = sellVaultToken;
        r.tokens[1] = buyVaultToken;

        r.clearingPrices = new uint256[](2);
        r.clearingPrices[0] = milkSwap.prices(IERC4626(sellVaultToken).asset());
        r.clearingPrices[1] = milkSwap.prices(IERC4626(buyVaultToken).asset()) * 1 ether / 0.98 ether;

        // Get trade data
        r.trades = new ICowSettlement.Trade[](1);
        (r.trades[0], r.orderData, r.orderUid) =
            setupCowOrder(r.tokens, 0, 1, sellAmount, buyAmount, validTo, owner, receiver, false);

        // Setup interactions - withdraw from sell vault, swap underlying assets, deposit to buy vault
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](4),
            new ICowSettlement.Interaction[](0)
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
        r.interactions[1][3] = ICowSettlement.Interaction({
            target: buyVaultToken,
            value: 0,
            callData: abi.encodeWithSignature("skim(uint256,address)", type(uint256).max, address(COW_SETTLEMENT))
        });
    }

    /// @notice Test swapping collateral from main account
    function test_CollateralSwapWrapper_MainAccount() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Create params using helper
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, user);

        // Get settlement data
        SettlementData memory settlement =
            getCollateralSwapSettlement(user, user, ESUSDS, EWBTC, DEFAULT_SWAP_AMOUNT, DEFAULT_BUY_AMOUNT);

        // User deposits SUSDS collateral
        vm.startPrank(user);
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);
        uint256 depositAmount = 1000e18;
        IERC4626(ESUSDS).deposit(depositAmount, user);

        // User signs the order and approves vault shares for settlement (already done in setupCowOrder)

        // Approve spending of the ESUSDS to repay debt
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);
        vm.stopPrank();

        // Record balances before swap
        uint256 susdsBalanceBefore = IERC20(ESUSDS).balanceOf(user);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(user);

        // Create permit signature and encode data
        bytes memory permitSignature = _createPermitSignature(params);
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, permitSignature);

        // Expect event emission
        vm.expectEmit(true, true, true, true);
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        // Execute wrapped settlement
        _executeWrappedSettlement(settleData, wrapperData);

        // Verify the collateral was swapped successfully
        assertEq(
            IERC20(ESUSDS).balanceOf(user),
            susdsBalanceBefore - DEFAULT_SWAP_AMOUNT,
            "User should have less ESUSDS after swap"
        );
        assertGt(IERC20(EWBTC).balanceOf(user), wbtcBalanceBefore, "User should have more EWBTC after swap");
    }

    /// @notice Test swapping collateral from subaccount
    function test_CollateralSwapWrapper_Subaccount() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        address account = address(uint160(user) ^ uint8(0x01));

        // Create params using helper
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, account);

        // Get settlement data - receiver is the subaccount
        SettlementData memory settlement =
            getCollateralSwapSettlement(user, account, ESUSDS, EWBTC, DEFAULT_SWAP_AMOUNT, DEFAULT_BUY_AMOUNT);

        // User deposits SUSDS collateral to subaccount
        vm.startPrank(user);
        IERC20(SUSDS).approve(ESUSDS, type(uint256).max);
        uint256 depositAmount = 1000e18;
        IERC4626(ESUSDS).deposit(depositAmount, account);

        // User signs the order on cowswap (already done in setupCowOrder)

        vm.stopPrank();

        // Setup subaccount approvals and pre-approved hash
        _setupSubaccountApprovals(account, params);

        // Record balances before swap
        uint256 susdsBalanceBefore = IERC20(ESUSDS).balanceOf(account);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(account);

        // Encode settlement and wrapper data (empty signature for pre-approved hash)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        // Expect event emission
        vm.expectEmit(true, true, true, true);
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        // Execute wrapped settlement
        _executeWrappedSettlement(settleData, wrapperData);

        // Verify the collateral was swapped successfully
        assertEq(
            IERC20(ESUSDS).balanceOf(account),
            susdsBalanceBefore - DEFAULT_SWAP_AMOUNT,
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
        address account = address(uint160(user) ^ uint8(0x01));
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, account);

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

        // Create params using helper
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, account);
        params.swapAmount = sellAmount; // Override swap amount for this test

        // Get settlement data
        SettlementData memory settlement =
            getCollateralSwapSettlement(user, account, ESUSDS, EWBTC, sellAmount, buyAmount);

        // User signs the order on cowswap (already done in setupCowOrder)

        // Setup subaccount approvals and pre-approved hash
        _setupSubaccountApprovals(account, params);

        // Record balances and debt before swap
        uint256 susdsBalanceBefore = IERC20(ESUSDS).balanceOf(account);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(account);
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement and wrapper data (empty signature for pre-approved hash)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        // Expect event emission
        vm.expectEmit(true, true, true, true);
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        // Execute wrapped settlement
        _executeWrappedSettlement(settleData, wrapperData);

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
