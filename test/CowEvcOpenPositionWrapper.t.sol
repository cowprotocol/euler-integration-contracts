// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {IEVault, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcOpenPositionWrapper} from "../src/CowEvcOpenPositionWrapper.sol";
import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcOpenPositionWrapper
/// @notice Tests the full flow of opening a leveraged position using the new wrapper contract
contract CowEvcOpenPositionWrapperTest is CowBaseTest {
    CowEvcOpenPositionWrapper public openPositionWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant USDS_MARGIN = 5000e18;
    uint256 constant DEFAULT_BORROW_AMOUNT = 1e18;
    uint256 constant DEFAULT_BUY_AMOUNT = 2500e18;
    uint256 constant MIN_BUY_SHARES_AMOUNT = 2400e18;

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

        // Setup user with USDS
        deal(address(USDS), user, 10000e18);
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
            collateralVault: address(EUSDS),
            borrowVault: address(EWETH),
            collateralAmount: USDS_MARGIN,
            borrowAmount: DEFAULT_BORROW_AMOUNT
        });
    }

    /// @notice Setup user approvals for pre-approved hash flow. This doesn't include the CoW order pre-signature because out of scope of testing, and handled elsewhere
    /// in order to simplify order creation.
    function _setupUserPreApprovedFlow(address account, bytes32 hash) internal {
        vm.startPrank(user);
        USDS.approve(address(EUSDS), type(uint256).max);
        EVC.setAccountOperator(user, address(openPositionWrapper), true);
        EVC.setAccountOperator(account, address(openPositionWrapper), true);
        openPositionWrapper.setPreApprovedHash(hash, true);
        vm.stopPrank();
    }

    /// @notice Create permit signature for EVC operator
    function _createPermitSignatureFor(
        CowEvcOpenPositionWrapper.OpenPositionParams memory params,
        uint256 userPrivateKey
    ) internal returns (bytes memory) {
        ecdsa.setPrivateKey(userPrivateKey);
        return ecdsa.signPermit(
            params.owner,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            params.deadline,
            0,
            openPositionWrapper.encodePermitData(params)
        );
    }

    /// @notice Verify position was opened successfully
    function _verifyPositionOpened(
        address account,
        IEVault collateralVaultToken,
        IEVault borrowVaultToken,
        uint256 expectedCollateral,
        uint256 expectedDebt,
        uint256 allowedDelta
    ) internal view {
        assertApproxEqAbs(
            collateralVaultToken.convertToAssets(collateralVaultToken.balanceOf(account)),
            expectedCollateral,
            allowedDelta,
            "User should have collateral deposited"
        );
        assertEq(borrowVaultToken.debtOf(account), expectedDebt, "User should have debt");
    }

    /// @notice Create settlement data for opening a leveraged position
    /// @dev Sells borrowed WETH to buy USDS which gets deposited into the vault
    function getOpenPositionSettlement(
        address owner,
        address receiver,
        IERC20 sellToken,
        IEVault buyVaultToken,
        uint256 sellAmount,
        uint256 buyAmount
    ) public returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create trade and extract order data

        // Get tokens and prices
        (r.tokens, r.clearingPrices) = getTokensAndPrices();

        r.trades = new ICowSettlement.Trade[](1);
        (r.trades[0], r.orderData, r.orderUid) = setupCowOrder({
            tokens: r.tokens,
            sellTokenIndex: 1,
            buyTokenIndex: 2,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            owner: owner,
            receiver: receiver,
            isBuy: false
        });

        // Setup interactions - swap WETH to USDS, deposit to vault
        // These are effectively the things that a solver would be doing in this sort of a situation with interactions
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](2),
            new ICowSettlement.Interaction[](0)
        ];
        // First interaction: convert the borrowed tokens on a DEX (Uniswap, for example)
        r.interactions[1][0] = getSwapInteraction(sellToken, IERC20(buyVaultToken.asset()), sellAmount);
        // Second interaction: The converted tokens get transferred to the euler vault (a "deposit")
        r.interactions[1][1] = getDepositInteraction(buyVaultToken, buyAmount);

        // By the way, it is technically possible to deposit without having to do a skim. But I find the parameters a bit more convenient, and an extra approval isnt required because we initiate the transfer.
    }

    /// @notice Test opening a leveraged position using the new wrapper
    function test_OpenPositionWrapper_Success() external {
        // Create params using helper
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = getOpenPositionSettlement({
            owner: user,
            receiver: account,
            sellToken: WETH,
            buyVaultToken: EUSDS,
            sellAmount: DEFAULT_BORROW_AMOUNT,
            buyAmount: MIN_BUY_SHARES_AMOUNT
        });

        // Setup user approvals
        vm.prank(user);
        USDS.approve(address(EUSDS), type(uint256).max);

        // User signs order
        // Does not need to run here because its done in `setupCowOrder`

        // Create permit signature
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // Verify that no position is open
        _verifyPositionOpened({
            account: account,
            collateralVaultToken: EUSDS,
            borrowVaultToken: EWETH,
            expectedCollateral: 0,
            expectedDebt: 0,
            allowedDelta: 0
        });

        // Encode settlement and wrapper data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, permitSignature));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcOpenPositionWrapper.CowEvcPositionOpened(
            params.owner,
            params.account,
            params.collateralVault,
            params.borrowVault,
            params.collateralAmount,
            params.borrowAmount
        );

        // Execute wrapped settlement
        openPositionWrapper.wrappedSettle(settleData, wrapperData);

        // Verify position was created successfully
        _verifyPositionOpened({
            account: account,
            collateralVaultToken: EUSDS,
            borrowVaultToken: EWETH,
            expectedCollateral: DEFAULT_BUY_AMOUNT + USDS_MARGIN,
            expectedDebt: DEFAULT_BORROW_AMOUNT,
            allowedDelta: 1 ether
        });
    }

    /// @notice Test opening a position with pre-approved hash (no signature needed)
    function test_OpenPositionWrapper_WithPreApprovedHash() external {
        // Create params using helper
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = getOpenPositionSettlement({
            owner: user,
            receiver: account,
            sellToken: WETH,
            buyVaultToken: EUSDS,
            sellAmount: DEFAULT_BORROW_AMOUNT,
            buyAmount: MIN_BUY_SHARES_AMOUNT
        });

        // Setup user approvals and pre-approve hash
        bytes32 hash = openPositionWrapper.getApprovalHash(params);
        _setupUserPreApprovedFlow(account, hash);

        // Verify that the operator is authorized before executing
        assertTrue(
            EVC.isAccountOperatorAuthorized(user, address(openPositionWrapper)),
            "Wrapper should be an authorized operator for the account before settle"
        );
        assertTrue(
            EVC.isAccountOperatorAuthorized(account, address(openPositionWrapper)),
            "Wrapper should be an authorized operator for the owner before settle"
        );

        // User pre-approves the order on CowSwap
        // Does not need to run here because it was signed as part of the settlement creation

        // Verify that no position is open to start with
        _verifyPositionOpened({
            account: account,
            collateralVaultToken: EUSDS,
            borrowVaultToken: EWETH,
            expectedCollateral: 0,
            expectedDebt: 0,
            allowedDelta: 0
        });

        // Encode settlement and wrapper data (empty signature since pre-approved)
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, new bytes(0)));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcOpenPositionWrapper.CowEvcPositionOpened(
            params.owner,
            params.account,
            params.collateralVault,
            params.borrowVault,
            params.collateralAmount,
            params.borrowAmount
        );

        // Execute wrapped settlement
        CowWrapper(address(openPositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the position was created successfully
        _verifyPositionOpened({
            account: account,
            collateralVaultToken: EUSDS,
            borrowVaultToken: EWETH,
            expectedCollateral: DEFAULT_BUY_AMOUNT + USDS_MARGIN,
            expectedDebt: DEFAULT_BORROW_AMOUNT,
            allowedDelta: 1 ether
        });

        // Verify that the operator has been revoked for the account after the operation
        // Verify that the operator is authorized before executing
        assertFalse(
            EVC.isAccountOperatorAuthorized(user, address(openPositionWrapper)),
            "Wrapper should no longer be an authorized operator for the account after settle"
        );
        assertFalse(
            EVC.isAccountOperatorAuthorized(account, address(openPositionWrapper)),
            "Wrapper should no longer be an authorized operator for the owner after settle"
        );
    }

    /// @notice Test that invalid signature causes the transaction to revert
    function test_OpenPositionWrapper_InvalidSignatureReverts() external {
        // Create params using helper
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = getOpenPositionSettlement({
            owner: user,
            receiver: account,
            sellToken: WETH,
            buyVaultToken: EUSDS,
            sellAmount: DEFAULT_BORROW_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT
        });

        // Setup user approvals
        vm.prank(user);
        USDS.approve(address(EUSDS), type(uint256).max);

        // Create INVALID permit signature by signing with wrong private key (user2's key instead of user's)
        ecdsa.setPrivateKey(privateKey2); // Wrong private key!
        bytes memory invalidPermitSignature = ecdsa.signPermit(
            params.owner,
            address(openPositionWrapper),
            openPositionWrapper.NONCE_NAMESPACE(),
            0,
            params.deadline,
            0,
            openPositionWrapper.encodePermitData(params)
        );

        // Encode settlement and wrapper data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
        bytes memory wrapperData = encodeWrapperData(abi.encode(params, invalidPermitSignature));

        // Execute wrapped settlement - should revert with EVC_NotAuthorized due to invalid signature
        vm.expectRevert(abi.encodeWithSignature("EVC_NotAuthorized()"));
        CowWrapper(address(openPositionWrapper)).wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test that the wrapper can handle being called three times in the same chain
    /// @dev Two users open positions in the same direction (long USDS), one user opens opposite (long WETH)
    function test_OpenPositionWrapper_ThreeUsers_TwoSameOneOpposite() external {
        // Setup User1: Has USDS, will borrow WETH and swap WETH→USDS (long USDS). Around 1 ETH
        deal(address(USDS), user, 2000 ether);

        // Approve USDS spending by eUSDS for user1
        vm.startPrank(user);
        USDS.approve(address(EUSDS), type(uint256).max);
        // Approve WETH for COW Protocol for user1
        WETH.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Setup User2: Has USDS, will borrow WETH and swap WETH→USDS. 3x the size (long USDS, same direction as user1). Around 3 ETH
        address account2 = address(uint160(user2) ^ 1);
        deal(address(USDS), user2, 5000 ether);

        // Approve USDS spending by eUSDS for user2
        vm.startPrank(user2);
        USDS.approve(address(EUSDS), type(uint256).max);

        // Approve WETH for COW Protocol for user2
        WETH.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Setup User3: Has WETH, will borrow USDS and swap USDS→WETH (long WETH, opposite direction). Around $5000
        address account3 = address(uint160(user3) ^ 1);
        deal(address(WETH), user3, 1 ether);

        // Approve WETH spending by eWETH for user2
        vm.startPrank(user3);
        WETH.approve(address(EWETH), type(uint256).max);
        // Approve USDS for COW Protocol for user3
        USDS.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

        vm.stopPrank();

        // Create params for User1: Deposit USDS, borrow WETH
        CowEvcOpenPositionWrapper.OpenPositionParams memory params1 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user,
            account: account,
            deadline: block.timestamp + 1 hours,
            collateralVault: address(EUSDS),
            borrowVault: address(EWETH),
            collateralAmount: 2000 ether,
            borrowAmount: 1 ether
        });

        // Create params for User2: Deposit USDS, borrow WETH (same direction as User1)
        CowEvcOpenPositionWrapper.OpenPositionParams memory params2 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user2,
            account: account2,
            deadline: block.timestamp + 1 hours,
            collateralVault: address(EUSDS),
            borrowVault: address(EWETH),
            collateralAmount: 5000 ether,
            borrowAmount: 3 ether
        });

        CowEvcOpenPositionWrapper.OpenPositionParams memory params3 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: user3,
            account: account3,
            deadline: block.timestamp + 1 hours,
            collateralVault: address(EWETH),
            borrowVault: address(EUSDS),
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
            openPositionWrapper.encodePermitData(params1)
        );

        ecdsa.setPrivateKey(privateKey2);
        bytes memory permitSignature2 = ecdsa.signPermit(
            params2.owner,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            params2.deadline,
            0,
            openPositionWrapper.encodePermitData(params2)
        );

        ecdsa.setPrivateKey(privateKey3);
        bytes memory permitSignature3 = ecdsa.signPermit(
            params3.owner,
            address(openPositionWrapper),
            uint256(uint160(address(openPositionWrapper))),
            0,
            params3.deadline,
            0,
            openPositionWrapper.encodePermitData(params3)
        );

        // Create settlement with all three trades
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Setup tokens array: WETH, eUSDS, USDS, eWETH
        (address[] memory tokens, uint256[] memory clearingPrices) = getTokensAndPrices();

        // Create trades and extract orders
        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](3);

        // Trade 1: User1 sells WETH for eUSDS
        (trades[0],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 1,
            buyTokenIndex: 2,
            sellAmount: params1.borrowAmount,
            buyAmount: 0,
            validTo: validTo,
            owner: user,
            receiver: account,
            isBuy: false
        });

        // Trade 2: User2 sells WETH for eUSDS (same direction as User1)
        (trades[1],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 1,
            buyTokenIndex: 2,
            sellAmount: params2.borrowAmount,
            buyAmount: 0,
            validTo: validTo,
            owner: user2,
            receiver: account2,
            isBuy: false
        });

        // Trade 3: User3 sells USDS for eWETH (opposite direction)
        (trades[2],,) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 3,
            sellAmount: params3.borrowAmount,
            buyAmount: 0,
            validTo: validTo,
            owner: user3,
            receiver: account3,
            isBuy: false
        });

        // Setup interactions to handle the swaps and deposits
        ICowSettlement.Interaction[][3] memory interactions;
        interactions[0] = new ICowSettlement.Interaction[](0);
        interactions[1] = new ICowSettlement.Interaction[](3);
        interactions[2] = new ICowSettlement.Interaction[](0);

        // Trade 1 & 2: coincidence of wants: WETH → USDS for the difference in all the users trades (2 WETH total difference)
        interactions[1][0] = getSwapInteraction(WETH, USDS, 2 ether);
        // Deposit USDS to eUSDS vault for both user1 and user2
        interactions[1][1] = getDepositInteraction(EUSDS, 10000 ether);
        // Deposit WETH to eWETH vault
        interactions[1][2] = getDepositInteraction(EWETH, 2 ether);

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

        // Execute wrapped settlement
        // Note: We don't use expectEmit here because there are many Transfer events
        // from the complex multi-user settlement that interfere with strict event matching
        openPositionWrapper.wrappedSettle(settleData, wrapperData);

        // Verify all three positions were opened successfully
        // User1: Should have USDS collateral and WETH debt
        _verifyPositionOpened({
            account: account,
            collateralVaultToken: EUSDS,
            borrowVaultToken: EWETH,
            expectedCollateral: 2000 ether + 2500 ether,
            expectedDebt: 1 ether,
            allowedDelta: 100 ether
        });

        // User2: Should have USDS collateral and WETH debt (same as User1)
        _verifyPositionOpened({
            account: account2,
            collateralVaultToken: EUSDS,
            borrowVaultToken: EWETH,
            expectedCollateral: 5000 ether + 7500 ether,
            expectedDebt: 3 ether,
            allowedDelta: 100 ether
        });

        // User3: Should have WETH collateral and USDS debt
        _verifyPositionOpened({
            account: account3,
            collateralVaultToken: EWETH,
            borrowVaultToken: EUSDS,
            expectedCollateral: 1 ether + 2 ether,
            expectedDebt: 5000 ether,
            allowedDelta: 0.1 ether
        });
    }
}
