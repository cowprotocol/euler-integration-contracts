// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcBaseWrapper} from "../src/CowEvcBaseWrapper.sol";
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

    uint256 constant USDS_MARGIN = 2000e18;
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

        // WBTC is not currently a collateral for WETH borrow, fix it
        vm.startPrank(IEVault(EWETH).governorAdmin());
        IEVault(EWETH).setLTV(EWBTC, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup user with USDS
        deal(USDS, user, 10000e18);

        // User has approved WBTC for COW Protocol
        address vaultRelayer = COW_SETTLEMENT.vaultRelayer();
        vm.prank(user);
        IERC20(WBTC).approve(vaultRelayer, type(uint256).max);
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
            fromVault: EUSDS,
            toVault: EWBTC,
            swapAmount: DEFAULT_SWAP_AMOUNT,
            kind: GPv2Order.KIND_SELL
        });
    }

    /// @notice Create permit signature for any user
    function _createPermitSignatureFor(
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params,
        uint256 userPrivateKey
    ) internal returns (bytes memory) {
        ecdsa.setPrivateKey(userPrivateKey);
        return ecdsa.signPermit(
            params.owner,
            address(collateralSwapWrapper),
            uint256(uint160(address(collateralSwapWrapper))),
            0,
            params.deadline,
            0,
            collateralSwapWrapper.encodePermitData(params)
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

    /// @notice Setup user approvals for collateral swap on subaccount
    function _setupSubaccountApprovals(CowEvcCollateralSwapWrapper.CollateralSwapParams memory params) internal {
        vm.startPrank(params.owner);

        // Approve vault shares from main account for settlement
        IEVault(params.fromVault).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        // Approve transfer of vault shares from the subaccount to wrapper
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: params.account,
            targetContract: params.fromVault,
            value: 0,
            data: abi.encodeCall(IERC20.approve, (address(collateralSwapWrapper), type(uint256).max))
        });
        EVC.batch(items);

        // Approve transfer of any remaining vault shares from the wrapper back to the subaccount
        IEVault(params.fromVault).approve(address(collateralSwapWrapper), type(uint256).max);

        // Set wrapper as operator for the subaccount
        EVC.setAccountOperator(params.account, address(collateralSwapWrapper), true);

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
        (r.trades[0], r.orderData, r.orderUid) = setupCowOrder({
            tokens: r.tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            owner: owner,
            receiver: receiver,
            isBuy: false
        });

        // Setup interactions - withdraw from sell vault, swap underlying assets, deposit to buy vault
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](3),
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
    }

    /// @notice Test swapping collateral from main account
    function test_CollateralSwapWrapper_MainAccount() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Create params using helper
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, user);

        // Get settlement data
        SettlementData memory settlement = getCollateralSwapSettlement({
            owner: user,
            receiver: user,
            sellVaultToken: EUSDS,
            buyVaultToken: EWBTC,
            sellAmount: DEFAULT_SWAP_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT
        });

        // User deposits USDS collateral
        vm.startPrank(user);
        IERC20(USDS).approve(EUSDS, type(uint256).max);
        uint256 depositAmount = 1000e18;
        IERC4626(EUSDS).deposit(depositAmount, user);

        // User signs the order and approves vault shares for settlement (already done in setupCowOrder)

        // Approve spending of the EUSDS to repay debt
        IEVault(EUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);
        vm.stopPrank();

        // Record balances before swap
        uint256 usdsBalanceBefore = IERC20(EUSDS).balanceOf(user);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(user);

        // Create permit signature and encode data
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, permitSignature);

        // Expect event emission
        vm.expectEmit();
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        // Execute wrapped settlement
        CowWrapper(address(collateralSwapWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the collateral was swapped successfully
        assertEq(
            IERC20(EUSDS).balanceOf(user),
            usdsBalanceBefore - DEFAULT_SWAP_AMOUNT,
            "User should have less EUSDS after swap"
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
        SettlementData memory settlement = getCollateralSwapSettlement({
            owner: user,
            receiver: account,
            sellVaultToken: EUSDS,
            buyVaultToken: EWBTC,
            sellAmount: DEFAULT_SWAP_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT
        });

        // User deposits USDS collateral to subaccount
        vm.startPrank(user);
        IERC20(USDS).approve(EUSDS, type(uint256).max);
        uint256 depositAmount = 1000e18;
        IERC4626(EUSDS).deposit(depositAmount, account);

        // User signs the order on cowswap (already done in setupCowOrder)

        vm.stopPrank();

        // Setup subaccount approvals and pre-approved hash
        _setupSubaccountApprovals(params);

        // Record balances before swap
        uint256 usdsBalanceBefore = IERC20(EUSDS).balanceOf(account);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(account);

        // Encode settlement and wrapper data (empty signature for pre-approved hash)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        // Execute wrapped settlement
        CowWrapper(address(collateralSwapWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the collateral was swapped successfully
        assertEq(
            IERC20(EUSDS).balanceOf(account),
            usdsBalanceBefore - DEFAULT_SWAP_AMOUNT,
            "Subaccount should have less EUSDS after swap"
        );
        assertGt(IERC20(EWBTC).balanceOf(account), wbtcBalanceBefore, "Subaccount should have more EWBTC after swap");

        // Main account balance should remain unchanged (transfer is atomic through settlement)
        assertEq(IERC20(EUSDS).balanceOf(user), 0, "Main account EUSDS balance should be 0");
    }

    /// @notice Test that invalid signature causes the transaction to revert
    function test_CollateralSwapWrapper_InvalidSignatureReverts() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Create params using helper (use user as both owner and account to avoid subaccount transfers)
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, user);

        // Get settlement data
        SettlementData memory settlement = getCollateralSwapSettlement({
            owner: user,
            receiver: user,
            sellVaultToken: EUSDS,
            buyVaultToken: EWBTC,
            sellAmount: DEFAULT_SWAP_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT
        });

        // User deposits USDS collateral
        vm.startPrank(user);
        IERC20(USDS).approve(EUSDS, type(uint256).max);
        uint256 depositAmount = 1000e18;
        IERC4626(EUSDS).deposit(depositAmount, user);

        // User approves vault shares for settlement
        IEVault(EUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);
        vm.stopPrank();

        // Create INVALID permit signature by signing with wrong private key (user2's key instead of user's)
        ecdsa.setPrivateKey(privateKey2); // Wrong private key!
        bytes memory invalidPermitSignature = ecdsa.signPermit(
            params.owner,
            address(collateralSwapWrapper),
            uint256(uint160(address(collateralSwapWrapper))),
            0,
            params.deadline,
            0,
            collateralSwapWrapper.encodePermitData(params)
        );

        // Encode settlement and wrapper data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, invalidPermitSignature);

        // Execute wrapped settlement - should revert with EVC_NotAuthorized due to invalid signature
        vm.expectRevert(abi.encodeWithSignature("EVC_NotAuthorized()"));
        CowWrapper(address(collateralSwapWrapper)).wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test that unauthorized users cannot call evcInternalSwap directly
    function test_CollateralSwapWrapper_UnauthorizedInternalSwap() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = "";

        // Try to call evcInternalSwap directly (not through EVC)
        vm.expectRevert(abi.encodeWithSelector(CowEvcBaseWrapper.Unauthorized.selector, address(this)));
        collateralSwapWrapper.evcInternalSettle(settleData, wrapperData, wrapperData);
    }

    /// @notice Test that non-solvers cannot call wrappedSettle
    function test_CollateralSwapWrapper_NonSolverCannotSettle() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        // Try to call wrappedSettle as non-solver
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, user));
        collateralSwapWrapper.wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test validateWrapperData function
    function test_CollateralSwapWrapper_ValidateWrapperData() external view {
        address account = address(uint160(user) ^ uint8(0x01));
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, account);

        bytes memory signature = new bytes(0);
        bytes memory wrapperData = abi.encode(params, signature);

        // Should not revert for valid wrapper data
        collateralSwapWrapper.validateWrapperData(wrapperData);
    }

    /// @notice Test swapping with a leveraged position (ensuring account health is maintained)
    function test_CollateralSwapWrapper_WithLeveragedPosition() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18; // Borrow 1 WETH
        uint256 collateralAmount = 2000e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // Set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount + borrowAmount * 2500e18 / 0.99e18,
            borrowAmount: borrowAmount
        });

        uint256 sellAmount = 1000 ether + 2500 ether; // Sell 3500 EUSDS
        uint256 buyAmount = 0.0325e8; // Expect to receive ~0.0325 EWBTC (8 decimals)

        // Create params using helper
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, account);
        params.swapAmount = sellAmount; // Override swap amount for this test

        // Get settlement data
        SettlementData memory settlement = getCollateralSwapSettlement({
            owner: user,
            receiver: account,
            sellVaultToken: EUSDS,
            buyVaultToken: EWBTC,
            sellAmount: sellAmount,
            buyAmount: buyAmount
        });

        // User signs the order on cowswap (already done in setupCowOrder)

        // Setup subaccount approvals and pre-approved hash
        _setupSubaccountApprovals(params);

        // Record balances and debt before swap
        uint256 susdsBalanceBefore = IERC20(EUSDS).balanceOf(account);
        uint256 wbtcBalanceBefore = IERC20(EWBTC).balanceOf(account);
        uint256 debtBefore = IEVault(EWETH).debtOf(account);

        // Encode settlement and wrapper data (empty signature for pre-approved hash)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.swapAmount, params.kind
        );

        // Execute wrapped settlement
        CowWrapper(address(collateralSwapWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the collateral was swapped successfully while maintaining debt
        assertEq(
            IERC20(EUSDS).balanceOf(account),
            susdsBalanceBefore - sellAmount,
            "Account should have less EUSDS after swap"
        );
        assertGt(IERC20(EWBTC).balanceOf(account), wbtcBalanceBefore, "Account should have more EWBTC after swap");
        assertEq(IEVault(EWETH).debtOf(account), debtBefore, "Debt should remain unchanged after swap");
    }

    /// @notice Test that the wrapper can handle being called three times in the same chain
    /// @dev Two users close positions in the same direction (long USDS), one user closes opposite (long WETH)
    function test_CollateralSwapWrapper_ThreeUsers_TwoSameOneOpposite() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Configure vault LTVs for both directions
        vm.startPrank(IEVault(EWETH).governorAdmin());
        IEVault(EWETH).setLTV(EUSDS, 0.9e4, 0.9e4, 0);
        IEVault(EWETH).setLTV(EWBTC, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup accounts
        address account1 = address(uint160(user) ^ 1);
        address account2 = address(uint160(user2) ^ 1);
        address account3 = address(uint160(user3) ^ 1);

        vm.label(account1, "account 1");
        vm.label(account2, "account 2");
        vm.label(account3, "account 3");

        // Setup User1: Long USDS (USDS collateral, WETH debt). 1 ETH debt
        setupLeveragedPositionFor({
            owner: user,
            account: account1,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 3750 ether,
            borrowAmount: 1 ether
        });

        // Setup User2: Long USDS (USDS collateral, WETH debt). 3 ETH debt
        setupLeveragedPositionFor({
            owner: user2,
            account: account2,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 12500 ether,
            borrowAmount: 3 ether
        });

        // Setup User3: Long WBTC (WETH collateral, WBTC debt). 2 ETH debt
        setupLeveragedPositionFor({
            owner: user3,
            account: account3,
            collateralVault: EWBTC,
            borrowVault: EWETH,
            collateralAmount: 0.075e8,
            borrowAmount: 2 ether
        });

        // Verify positions exist
        assertEq(IEVault(EWETH).debtOf(account1), 1 ether, "Account 1 should have WETH debt");
        assertEq(IEVault(EWETH).debtOf(account2), 3 ether, "Account 2 should have WETH debt");
        assertEq(IEVault(EWETH).debtOf(account3), 2 ether, "Account 3 should have WETH debt");

        // Verify collaterals
        assertApproxEqRel(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account1)),
            3750 ether,
            0.01 ether,
            "Account 1 should have USDS collateral"
        );
        assertApproxEqRel(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account2)),
            12500 ether,
            0.01 ether,
            "Account 2 should have USDS collateral"
        );
        assertApproxEqRel(
            IERC4626(EWBTC).convertToAssets(IEVault(EWBTC).balanceOf(account3)),
            0.075e8,
            0.01 ether,
            "Account 3 should have WBTC collateral"
        );

        // Create params for all users
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params1 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user,
                account: account1,
                deadline: block.timestamp + 1 hours,
                fromVault: EUSDS,
                toVault: EWBTC,
                swapAmount: 500 ether,
                kind: GPv2Order.KIND_SELL
            });

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params2 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user2,
                account: account2,
                deadline: block.timestamp + 1 hours,
                fromVault: EUSDS,
                toVault: EWBTC,
                swapAmount: 0.005e8, // about 500 EUSDS
                kind: GPv2Order.KIND_BUY
            });

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params3 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user3,
                account: account3,
                deadline: block.timestamp + 1 hours,
                fromVault: EWBTC,
                toVault: EUSDS,
                swapAmount: 2000 ether,
                kind: GPv2Order.KIND_BUY
            });

        // Create permit signatures for all users
        bytes memory permitSignature1 = _createPermitSignatureFor(params1, privateKey);
        bytes memory permitSignature2 = _createPermitSignatureFor(params2, privateKey2);
        bytes memory permitSignature3 = _createPermitSignatureFor(params3, privateKey3);

        // Setup approvals for all users
        _setupSubaccountApprovals(params1);
        _setupSubaccountApprovals(params2);
        _setupSubaccountApprovals(params3);

        // Create settlement with all three trades
        uint32 validTo = uint32(block.timestamp + 1 hours);

        address[] memory tokens = new address[](2);
        tokens[0] = EUSDS;
        tokens[1] = EWBTC;

        uint256[] memory clearingPrices = new uint256[](2);
        clearingPrices[0] = 1 ether; // eUSDS price
        clearingPrices[1] = 100000 ether * 1e10; // eWBTC price

        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](3);
        (trades[0],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: params1.swapAmount,
            buyAmount: 0,
            validTo: validTo,
            owner: user,
            receiver: account1,
            isBuy: false
        });
        (trades[1],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: 1e24,
            buyAmount: params2.swapAmount,
            validTo: validTo,
            owner: user2,
            receiver: account2,
            isBuy: true
        });
        (trades[2],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 1,
            buyTokenIndex: 0,
            sellAmount: 1e24,
            buyAmount: params3.swapAmount,
            validTo: validTo,
            owner: user3,
            receiver: account3,
            isBuy: true
        });

        // Setup interactions
        ICowSettlement.Interaction[][3] memory interactions;
        interactions[0] = new ICowSettlement.Interaction[](0);
        interactions[1] = new ICowSettlement.Interaction[](3);
        interactions[2] = new ICowSettlement.Interaction[](0);

        // We pull the money out of the euler vaults
        interactions[1][0] = getWithdrawInteraction(EWBTC, 0.01e8);

        // We swap all of the WBTC we need
        interactions[1][1] = getSwapInteraction(WBTC, USDS, 0.01e8);

        // We deposit back into WBTC
        interactions[1][2] = getDepositInteraction(EUSDS, 1000 ether);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(ICowSettlement.settle, (tokens, clearingPrices, trades, interactions));

        // Chain wrapper data
        bytes memory wrapper1Data = abi.encode(params1, permitSignature1);
        bytes memory wrapper2Data = abi.encode(params2, permitSignature2);
        bytes memory wrapper3Data = abi.encode(params3, permitSignature3);

        bytes memory wrapperData = abi.encodePacked(
            uint16(wrapper1Data.length),
            wrapper1Data,
            address(collateralSwapWrapper),
            uint16(wrapper2Data.length),
            wrapper2Data,
            address(collateralSwapWrapper),
            uint16(wrapper3Data.length),
            wrapper3Data
        );

        // Execute wrapped settlement
        collateralSwapWrapper.wrappedSettle(settleData, wrapperData);

        // Verify all positions closed successfully
        assertEq(IEVault(EWETH).debtOf(account1), 1 ether, "User1 should have WETH debt");
        assertEq(IEVault(EWETH).debtOf(account2), 3 ether, "User2 should have WETH debt");
        assertEq(IEVault(EWETH).debtOf(account3), 2 ether, "User3 should have WETH debt");

        // Verify original collaterals
        assertApproxEqRel(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account1)),
            3250 ether,
            0.01 ether,
            "Account 1 should have less USDS collateral"
        );
        assertApproxEqRel(
            IERC4626(EUSDS).convertToAssets(IEVault(EUSDS).balanceOf(account2)),
            12000 ether,
            0.01 ether,
            "Account 2 should have less USDS collateral"
        );
        assertApproxEqRel(
            IEVault(EWBTC).balanceOf(account3), 0.055e8, 0.01 ether, "Account 3 should have less WBTC collateral"
        );

        // Verify new collaterals
        assertApproxEqRel(
            IEVault(EWBTC).balanceOf(account1), 0.005e8, 0.01 ether, "Account 1 should have some WBTC collateral"
        );
        assertEq(IEVault(EWBTC).balanceOf(account2), 0.005e8, "Account 2 should have some WBTC collateral");
        assertEq(IEVault(EUSDS).balanceOf(account3), 2000 ether, "Account 3 should have some USDS collateral");
    }
}
