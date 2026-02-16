// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {IEVault, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcClosePositionWrapper} from "../src/CowEvcClosePositionWrapper.sol";
import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {Inbox} from "../src/Inbox.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcClosePositionWrapper
/// @notice Tests the full flow of closing a leveraged position using the new wrapper contract
contract CowEvcClosePositionWrapperTest is CowBaseTest {
    CowEvcClosePositionWrapper public closePositionWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant USDS_MARGIN = 3000e18;
    uint256 constant DEFAULT_SELL_AMOUNT = 2900 ether; // would repay all debt by a large margin
    uint256 constant DEFAULT_BUY_AMOUNT = 1.12 ether;

    // when repaying, if no time passes, we should have exactly 0.001 eth left over
    uint256 constant DEFAULT_BUY_REPAID = 1 ether;
    uint256 constant DEFAULT_BUY_LEFTOVER = 0.12 ether;

    function setUp() public override {
        super.setUp();

        // Deploy the new close position wrapper
        closePositionWrapper = new CowEvcClosePositionWrapper(address(EVC), COW_SETTLEMENT);
        wrapper = closePositionWrapper;

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(closePositionWrapper));
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
            borrowVault: address(EWETH),
            collateralVault: address(EUSDS),
            collateralAmount: DEFAULT_SELL_AMOUNT
        });
    }

    /// @notice Setup pre-approved hash flow for close position
    function _setupPreApprovedFlow(address owner, address account, bytes32 hash) internal {
        vm.startPrank(owner);

        // Set operators
        EVC.setAccountOperator(account, address(closePositionWrapper), true);

        // Pre-approve hash
        closePositionWrapper.setPreApprovedHash(hash, true);

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

    /// @notice Encode settlement data for ICowSettlement.settle call
    function _encodeSettleData(SettlementData memory settlement) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
    }

    /// @notice Encode close position wrapper data with length prefix
    /// @dev Combines encoding params+signature and adding length prefix
    function _encodeClosePositionWrapperData(
        CowEvcClosePositionWrapper.ClosePositionParams memory params,
        bytes memory signature
    ) internal pure returns (bytes memory) {
        return encodeWrapperData(abi.encode(params, signature));
    }

    /// @notice Create settlement data for closing a leveraged position with EIP-1271 signature
    /// @dev Sells vault shares to buy repayment token (WETH), using Inbox EIP-1271 signature
    function prepareAndSignClosePositionSettlementWithInbox(
        address owner,
        address account,
        IEVault sellVaultToken,
        IERC20 buyToRepayToken,
        uint256 sellAmount,
        uint256 buyAmount,
        uint256 userPrivateKey
    ) public view returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Get tokens and prices
        r.tokens = new address[](2);
        r.tokens[0] = address(sellVaultToken);
        r.tokens[1] = address(buyToRepayToken);

        r.clearingPrices = new uint256[](2);
        r.clearingPrices[0] = milkSwap.prices(sellVaultToken.asset());
        r.clearingPrices[1] = milkSwap.prices(address(buyToRepayToken));

        // Get trade data using EIP-1271
        r.trades = new ICowSettlement.Trade[](1);

        (address inboxAddress, bytes32 inboxDomainSeparator) =
            closePositionWrapper.getInboxAddressAndDomainSeparator(owner, account);

        (r.trades[0], r.orderData, r.orderUid) = setupCowOrderWithInbox({
            tokens: r.tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            receiver: inboxAddress,
            inboxDomainSeparator: inboxDomainSeparator,
            isBuy: true,
            signerPrivateKey: userPrivateKey
        });

        // Setup interactions - withdraw from vault, swap to repayment token
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](2),
            new ICowSettlement.Interaction[](0)
        ];
        r.interactions[1][0] = getWithdrawInteraction(sellVaultToken, buyAmount * r.clearingPrices[1] / 1e18);
        r.interactions[1][1] =
            getSwapInteraction(IERC20(sellVaultToken.asset()), buyToRepayToken, buyAmount * r.clearingPrices[1] / 1e18);
    }

    /// @notice Test closing a leveraged position using the wrapper with EIP-1271 signatures
    function test_ClosePositionWrapper_Permit_SuccessFullRepay() external {
        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
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

        // Get settlement data using EIP-1271
        SettlementData memory settlement = prepareAndSignClosePositionSettlementWithInbox({
            owner: user,
            account: account,
            sellVaultToken: EUSDS,
            buyToRepayToken: WETH,
            sellAmount: DEFAULT_SELL_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT,
            userPrivateKey: privateKey
        });

        // Create permit signature
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // Record balances before closing
        uint256 collateralBefore = EUSDS.balanceOf(user);
        uint256 collateralBeforeAccount = EUSDS.balanceOf(account);

        // Encode settlement and wrapper data
        bytes memory settleData = _encodeSettleData(settlement);
        bytes memory wrapperData = _encodeClosePositionWrapperData(params, permitSignature);

        // Expect event emission
        vm.expectEmit();
        emit CowEvcClosePositionWrapper.CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            DEFAULT_BUY_REPAID,
            DEFAULT_BUY_LEFTOVER
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");

        // We're testing a buy order, so the execution should only take the minimum amount needed
        // from the user to pay for the proceeds at the settlement price.
        // DEFAULT_SELL_AMOUNT EUSDS is still pulled out of the wallet, but the rest should be
        // returned to the account.
        // Note: 2500 is the price in the settlement.
        uint256 expectedProceeds = DEFAULT_BUY_AMOUNT * 2500;
        assertEq(
            EUSDS.balanceOf(account),
            collateralBeforeAccount - expectedProceeds,
            "User final balance should account for buy order surplus"
        );
        assertNotEq(
            expectedProceeds,
            DEFAULT_SELL_AMOUNT,
            "We want to test that leftovers are sent back but there are no leftovers"
        );

        assertEq(
            WETH.balanceOf(user), DEFAULT_BUY_LEFTOVER, "User should have any surplus WETH left over after repaying"
        );
        assertEq(EUSDS.balanceOf(user), collateralBefore, "User main account balance should not have changed");
    }

    /// @notice Test shrinking the position with partial repayment using EIP-1271
    function test_ClosePositionWrapper_Permit_PartialRepay() external {
        uint256 borrowAmount = 2e18;
        uint256 collateralAmount = USDS_MARGIN + 4990e18;
        uint256 sellAmount = 2500e18;
        uint256 buyAmount = 0.98e18;

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params with custom amounts
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);
        params.collateralAmount = sellAmount;

        // Get settlement data using EIP-1271
        SettlementData memory settlement = prepareAndSignClosePositionSettlementWithInbox({
            owner: user,
            account: account,
            sellVaultToken: EUSDS,
            buyToRepayToken: WETH,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            userPrivateKey: privateKey
        });

        // Create permit signature
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // Encode settlement and wrapper data
        bytes memory settleData = _encodeSettleData(settlement);
        bytes memory wrapperData = _encodeClosePositionWrapperData(params, permitSignature);

        // Expect event emission
        vm.expectEmit();
        emit CowEvcClosePositionWrapper.CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            buyAmount,
            0
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify partial repayment
        uint256 debtAfter = IEVault(EWETH).debtOf(account);
        assertEq(debtAfter, borrowAmount - buyAmount, "Debt should be reduced by repaid amount");
        assertEq(WETH.balanceOf(user), 0, "User should have used any collateral they received to repay");
    }

    /// @notice Test closing a position with pre-approved hash (no signature needed)
    function test_ClosePositionWrapper_PreApprove_SuccessFullRepay() external {
        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params using helper
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = prepareAndSignClosePositionSettlementWithInbox({
            owner: user,
            account: account,
            sellVaultToken: EUSDS,
            buyToRepayToken: WETH,
            sellAmount: DEFAULT_SELL_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT,
            userPrivateKey: 0 // triggers pre-approved signature type
        });

        // Setup pre-approved flow
        bytes32 hash = closePositionWrapper.getApprovalHash(params);
        _setupPreApprovedFlow(user, account, hash);

        // The inbox needs to be deployed in advance. Anyone can deploy the inbox with a call to `getInbox`
        Inbox inbox = Inbox(closePositionWrapper.getInbox(user, account));

        // The pre approved flow requires setting a signature on the inbox (not on the settlement because the inbox is what sends the order)
        vm.prank(user);
        inbox.setPreSignature(settlement.orderUid, true);

        // Verify that the operator is authorized before executing
        assertTrue(
            EVC.isAccountOperatorAuthorized(account, address(closePositionWrapper)),
            "Wrapper should be an authorized operator for the account before settle"
        );

        // Record balances before closing
        uint256 debtBefore = EWETH.debtOf(account);
        uint256 collateralBefore = EUSDS.balanceOf(user);
        uint256 collateralBeforeAccount = EUSDS.balanceOf(account);
        assertEq(debtBefore, borrowAmount, "User should start with debt");

        // Encode settlement and wrapper data (empty signature since pre-approved)
        bytes memory settleData = _encodeSettleData(settlement);
        // An empty signature signifies that the wrapper needs to use the pre-sign flow and not the permit flow
        bytes memory wrapperData = _encodeClosePositionWrapperData(params, new bytes(0));

        // Expect event emission
        vm.expectEmit();
        emit CowEvcClosePositionWrapper.CowEvcPositionClosed(
            params.owner,
            params.account,
            params.borrowVault,
            params.collateralVault,
            params.collateralAmount,
            DEFAULT_BUY_REPAID,
            DEFAULT_BUY_LEFTOVER
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");
        assertApproxEqRel(
            EUSDS.balanceOf(account),
            // the amount of ether *actually sold* should be very close to.
            // While 2900 EUSDS is pulled out of the wallet, only 2800 (1.12 ETH * $2500) would be spent, and the rest returned to the account.
            collateralBeforeAccount - 2800 ether,
            0.01 ether,
            "User should have used approximately 2500 EUSDS to repay after closing"
        );
        assertEq(EUSDS.balanceOf(user), collateralBefore, "User main account balance should not have changed");
        assertEq(
            WETH.balanceOf(user), DEFAULT_BUY_LEFTOVER, "User should have any surplus WETH left over after repaying"
        );

        // Verify that the operator has been revoked for the account after the operation
        assertFalse(
            EVC.isAccountOperatorAuthorized(account, address(closePositionWrapper)),
            "Wrapper should no longer be an operator for the account"
        );

        assertFalse(closePositionWrapper.isHashPreApproved(user, hash), "Pre-approved hash should be cleared after use");
    }

    /// @notice Test that invalid signature causes the transaction to revert with EIP-1271
    function test_ClosePositionWrapper_InvalidSignatureReverts() external {
        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ 1);

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params using helper
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data using EIP-1271
        SettlementData memory settlement = prepareAndSignClosePositionSettlementWithInbox({
            owner: user,
            account: account,
            sellVaultToken: EUSDS,
            buyToRepayToken: WETH,
            sellAmount: DEFAULT_SELL_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT,
            userPrivateKey: privateKey2 // Use wrong private key to create invalid signature
        });

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
        bytes memory settleData = _encodeSettleData(settlement);
        bytes memory wrapperData = _encodeClosePositionWrapperData(params, invalidPermitSignature);

        // Execute wrapped settlement - should revert with EVC_NotAuthorized due to invalid signature
        vm.expectRevert(abi.encodeWithSignature("EVC_NotAuthorized()"));
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test that UnexpectedRepayResult is triggered when repay returns different amount
    function test_ClosePositionWrapper_UnexpectedRepayResult() external {
        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = USDS_MARGIN + 2495e18;

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
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

        // Get settlement data using EIP-1271
        SettlementData memory settlement = prepareAndSignClosePositionSettlementWithInbox({
            owner: user,
            account: account,
            sellVaultToken: EUSDS,
            buyToRepayToken: WETH,
            sellAmount: DEFAULT_SELL_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT,
            userPrivateKey: privateKey
        });

        // Create permit signature
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // Encode settlement and wrapper data
        bytes memory settleData = _encodeSettleData(settlement);
        bytes memory wrapperData = _encodeClosePositionWrapperData(params, permitSignature);

        // Mock the vault's repay function to return a different amount than requested
        // We expect DEFAULT_BUY_REPAID (1 ether) to be repaid, but mock returns 0.5 ether
        uint256 expectedRepayAmount = DEFAULT_BUY_REPAID;
        uint256 mockReturnAmount = 0.5 ether;

        // Mock the repay call on the borrow vault (EWETH)
        // The repay function is called with (amount, account) and returns the amount repaid
        vm.mockCall(
            address(EWETH),
            abi.encodeWithSelector(IBorrowing.repay.selector, expectedRepayAmount, account),
            abi.encode(mockReturnAmount)
        );

        // Expect the UnexpectedRepayResult error
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcClosePositionWrapper.UnexpectedRepayResult.selector, expectedRepayAmount, mockReturnAmount
            )
        );

        // Execute wrapped settlement - should revert with UnexpectedRepayResult
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test that the wrapper can handle being called three times in the same chain
    /// @dev Two users close positions in the same direction (long USDS), one user closes opposite (long WETH)
    function test_ClosePositionWrapper_ThreeUsers_TwoSameOneOpposite() external {
        // Setup User1: Long USDS (USDS collateral, WETH debt). ~1 ETH debt
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 5500 ether,
            borrowAmount: 1 ether
        });

        // Setup User2: Long USDS (USDS collateral, WETH debt). ~3 ETH debt
        setupLeveragedPositionFor({
            owner: user2,
            ownerAccount: account2,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 12000 ether,
            borrowAmount: 3 ether
        });

        // Setup User3: Long WETH (WETH collateral, USDS debt). ~5000 USDS debt
        setupLeveragedPositionFor({
            owner: user3,
            ownerAccount: account3,
            collateralVault: EWETH,
            borrowVault: EUSDS,
            collateralAmount: 3 ether,
            borrowAmount: 5000 ether
        });

        // Verify positions exist
        assertEq(EWETH.debtOf(account), 1 ether, "User1 should have WETH debt");
        assertEq(EWETH.debtOf(account2), 3 ether, "User2 should have WETH debt");
        assertEq(EUSDS.debtOf(account3), 5000 ether, "User3 should have USDS debt");

        // confirm the amounts before repayment
        assertApproxEqAbs(
            EUSDS.convertToAssets(EUSDS.balanceOf(account)),
            5500 ether,
            1 ether,
            "User1 should have some EUSDS collateral before closing"
        );
        assertApproxEqAbs(
            EUSDS.convertToAssets(EUSDS.balanceOf(account2)),
            12000 ether,
            1 ether,
            "User2 should have some EUSDS collateral before closing"
        );
        assertApproxEqAbs(
            EWETH.convertToAssets(EWETH.balanceOf(account3)),
            3 ether,
            0.01 ether,
            "User3 should have some EWETH collateral before closing"
        );

        // Create params for all users
        CowEvcClosePositionWrapper.ClosePositionParams memory params1 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(EWETH),
            collateralVault: address(EUSDS),
            collateralAmount: 2550 ether
        });

        CowEvcClosePositionWrapper.ClosePositionParams memory params2 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user2,
            account: account2,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(EWETH),
            collateralVault: address(EUSDS),
            collateralAmount: 7600 ether
        });

        CowEvcClosePositionWrapper.ClosePositionParams memory params3 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user3,
            account: account3,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(EUSDS),
            collateralVault: address(EWETH),
            collateralAmount: 2.1 ether
        });

        // Create permit signatures for all users
        bytes memory permitSignature1 = _createPermitSignatureFor(params1, privateKey);
        bytes memory permitSignature2 = _createPermitSignatureFor(params2, privateKey2);
        bytes memory permitSignature3 = _createPermitSignatureFor(params3, privateKey3);

        // Create settlement with all three trades using EIP-1271
        uint32 validTo = uint32(block.timestamp + 1 hours);

        (address[] memory tokens, uint256[] memory clearingPrices) = getTokensAndPrices();

        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](3);
        {
            (address inboxAddress, bytes32 inboxDomainSeparator) =
                closePositionWrapper.getInboxAddressAndDomainSeparator(user, account);
            (trades[0],,) = setupCowOrderWithInbox({
                tokens: tokens,
                sellTokenIndex: 2,
                buyTokenIndex: 1,
                sellAmount: params1.collateralAmount,
                buyAmount: 1.001 ether,
                validTo: validTo,
                receiver: inboxAddress,
                isBuy: true,
                inboxDomainSeparator: inboxDomainSeparator,
                signerPrivateKey: privateKey
            });
        }
        {
            (address inboxAddress, bytes32 inboxDomainSeparator) =
                closePositionWrapper.getInboxAddressAndDomainSeparator(user2, account2);
            (trades[1],,) = setupCowOrderWithInbox({
                tokens: tokens,
                sellTokenIndex: 2,
                buyTokenIndex: 1,
                sellAmount: params2.collateralAmount,
                buyAmount: 3.003 ether,
                validTo: validTo,
                receiver: inboxAddress,
                isBuy: true,
                inboxDomainSeparator: inboxDomainSeparator,
                signerPrivateKey: privateKey2
            });
        }
        {
            (address inboxAddress, bytes32 inboxDomainSeparator) =
                closePositionWrapper.getInboxAddressAndDomainSeparator(user3, account3);

            (trades[2],,) = setupCowOrderWithInbox({
                tokens: tokens,
                sellTokenIndex: 3,
                buyTokenIndex: 0,
                sellAmount: params3.collateralAmount,
                buyAmount: 5005 ether,
                validTo: validTo,
                receiver: inboxAddress,
                isBuy: true,
                inboxDomainSeparator: inboxDomainSeparator,
                signerPrivateKey: privateKey3
            });
        }

        // Setup interactions
        ICowSettlement.Interaction[][3] memory interactions;
        interactions[0] = new ICowSettlement.Interaction[](0);
        interactions[1] = new ICowSettlement.Interaction[](3);
        interactions[2] = new ICowSettlement.Interaction[](0);

        // We pull the money out of the euler vaults
        interactions[1][0] =
            getWithdrawInteraction(EUSDS, (1.001 ether + 3.003 ether) * clearingPrices[1] / clearingPrices[0]);
        interactions[1][1] = getWithdrawInteraction(EWETH, 5005 ether * clearingPrices[0] / clearingPrices[1]);

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
        assertEq(EWETH.debtOf(account), 0, "User1 should have no WETH debt after closing");
        assertEq(EWETH.debtOf(account2), 0, "User2 should have no WETH debt after closing");
        assertEq(EUSDS.debtOf(account3), 0, "User3 should have no USDS debt after closing");

        // confirm the amounts after repayment
        assertApproxEqAbs(
            EUSDS.convertToAssets(EUSDS.balanceOf(account)),
            5500 ether - 2502.5 ether,
            1 ether,
            "User1 should have some EUSDS collateral after closing"
        );
        assertApproxEqAbs(
            EUSDS.convertToAssets(EUSDS.balanceOf(account2)),
            12000 ether - 7507.5 ether,
            1 ether,
            "User2 should have some EUSDS collateral after closing"
        );
        assertApproxEqAbs(
            EWETH.convertToAssets(EWETH.balanceOf(account3)),
            3 ether - 2 ether,
            0.01 ether,
            "User3 should have some EWETH collateral after closing"
        );
    }
}
