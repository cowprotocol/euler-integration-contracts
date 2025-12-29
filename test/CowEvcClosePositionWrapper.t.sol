// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";
import {IERC20 as CowERC20} from "cow/interfaces/IERC20.sol";

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {IEVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcClosePositionWrapper} from "../src/CowEvcClosePositionWrapper.sol";
import {CowEvcBaseWrapper} from "../src/CowEvcBaseWrapper.sol";
import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {PreApprovedHashes} from "../src/PreApprovedHashes.sol";
import {Inbox} from "../src/Inbox.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {SignerECDSA} from "./helpers/SignerECDSA.sol";

/// @title E2E Test for CowEvcClosePositionWrapper
/// @notice Tests the full flow of closing a leveraged position using the new wrapper contract
contract CowEvcClosePositionWrapperTest is CowBaseTest {
    CowEvcClosePositionWrapper public closePositionWrapper;
    SignerECDSA internal ecdsa;

    uint256 constant SUSDS_MARGIN = 2000e18;
    uint256 constant DEFAULT_SELL_AMOUNT = 2510 ether;
    uint256 constant DEFAULT_BUY_AMOUNT = 1.001 ether;

    // when repaying, if no time passes, we should have exactly 0.001 eth left over
    uint256 constant DEFAULT_BUY_REPAID = 1 ether;
    uint256 constant DEFAULT_BUY_LEFTOVER = 0.001 ether;

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

        // sUSDS is not currently a collateral for WETH borrow, fix it
        vm.startPrank(IEVault(EWETH).governorAdmin());
        IEVault(EWETH).setLTV(ESUSDS, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup user with SUSDS
        deal(SUSDS, user, 10000e18);
    }

    /// @notice Helper to create or get Inbox for a user and account
    function _getOrCreateInbox(address owner) internal returns (Inbox) {
        return closePositionWrapper.getInbox(owner, owner) != address(0)
            ? Inbox(closePositionWrapper.getInbox(owner, owner))
            : Inbox(closePositionWrapper.getInbox(owner, owner));
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
            collateralVault: ESUSDS,
            collateralAmount: DEFAULT_SELL_AMOUNT,
            minRepay: DEFAULT_BUY_AMOUNT,
            kind: GPv2Order.KIND_BUY,
            appData: bytes32(0)
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
            targetContract: ESUSDS,
            value: 0,
            data: abi.encodeCall(IERC20.approve, (address(closePositionWrapper), type(uint256).max))
        });
        EVC.batch(items);

        // Approve the wrapper to send excess tokens back to the subaccount they came from
        IEVault(ESUSDS).approve(address(closePositionWrapper), type(uint256).max);

        // Approve vault shares for settlement
        IEVault(ESUSDS).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max);

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
        // NOTE: this permit signature differs from the other wrappers as we are signing *WITH THE SUBACCOUNT*
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

    /// @notice Create settlement data for closing a leveraged position
    /// @dev Sells vault shares to buy repayment token (WETH)
    function getClosePositionSettlement(
        address owner,
        address account,
        address sellVaultToken,
        address buyToRepayToken,
        uint256 sellAmount,
        uint256 buyAmount
    ) public returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Get tokens and prices
        r.tokens = new address[](2);
        r.tokens[0] = sellVaultToken;
        r.tokens[1] = buyToRepayToken;

        r.clearingPrices = new uint256[](2);
        r.clearingPrices[0] = milkSwap.prices(IERC4626(sellVaultToken).asset());
        r.clearingPrices[1] = milkSwap.prices(buyToRepayToken);

        // Get trade data
        r.trades = new ICowSettlement.Trade[](1);
        (r.trades[0], r.orderData, r.orderUid) = setupCowOrderEIP1271({
            tokens: r.tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            signer: owner,
            account: account,
            receiver: closePositionWrapper.getInbox(user, account),
            isBuy: true,
            signerPrivateKey: privateKey
        });

        // Setup interactions - withdraw from vault, swap to repayment token
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](2),
            new ICowSettlement.Interaction[](0)
        ];
        r.interactions[1][0] = getWithdrawInteraction(sellVaultToken, buyAmount * r.clearingPrices[1] / 1e18);
        r.interactions[1][1] = getSwapInteraction(
            IERC4626(sellVaultToken).asset(), buyToRepayToken, buyAmount * r.clearingPrices[1] / 1e18
        );
    }

    /// @notice Create settlement data for closing a leveraged position with EIP-1271 signature
    /// @dev Sells vault shares to buy repayment token (WETH), using Inbox EIP-1271 signature
    function getClosePositionSettlementEIP1271(
        address owner,
        address account,
        address sellVaultToken,
        address buyToRepayToken,
        uint256 sellAmount,
        uint256 buyAmount,
        uint256 userPrivateKey,
        bool isBuy
    ) public returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Get tokens and prices
        r.tokens = new address[](2);
        r.tokens[0] = sellVaultToken;
        r.tokens[1] = buyToRepayToken;

        r.clearingPrices = new uint256[](2);
        r.clearingPrices[0] = milkSwap.prices(IERC4626(sellVaultToken).asset());
        r.clearingPrices[1] = milkSwap.prices(buyToRepayToken);

        // Get trade data using EIP-1271
        r.trades = new ICowSettlement.Trade[](1);
        (r.trades[0], r.orderData, r.orderUid) = setupCowOrderEIP1271({
            tokens: r.tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            signer: owner,
            account: account,
            receiver: closePositionWrapper.getInbox(owner, account),
            isBuy: isBuy,
            signerPrivateKey: userPrivateKey
        });

        // Setup interactions - withdraw from vault, swap to repayment token
        r.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](2),
            new ICowSettlement.Interaction[](0)
        ];
        r.interactions[1][0] = getWithdrawInteraction(sellVaultToken, buyAmount * r.clearingPrices[1] / 1e18);
        r.interactions[1][1] = getSwapInteraction(
            IERC4626(sellVaultToken).asset(), buyToRepayToken, buyAmount * r.clearingPrices[1] / 1e18
        );
    }

    /// @notice Test closing a leveraged position using the wrapper with EIP-1271 signatures
    function test_ClosePositionWrapper_SuccessFullRepay() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = SUSDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: ESUSDS,
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
        SettlementData memory settlement = getClosePositionSettlementEIP1271({
            owner: user,
            account: account,
            sellVaultToken: ESUSDS,
            buyToRepayToken: WETH,
            sellAmount: DEFAULT_SELL_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT,
            userPrivateKey: privateKey,
            isBuy: true
        });

        // Setup approvals
        _setupClosePositionApprovalsFor(user, account, ESUSDS, WETH);

        // Create permit signature
        bytes memory permitSignature = _createPermitSignatureFor(params, privateKey);

        // Record balances before closing
        uint256 collateralBefore = IERC20(ESUSDS).balanceOf(user);
        uint256 collateralBeforeAccount = IERC20(ESUSDS).balanceOf(account);

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
            DEFAULT_BUY_REPAID,
            DEFAULT_BUY_LEFTOVER
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");
        assertLt(
            IERC20(ESUSDS).balanceOf(account), collateralBeforeAccount, "User should have less collateral after closing"
        );
        assertEq(IERC20(ESUSDS).balanceOf(user), collateralBefore, "User main account balance should not have changed");
        assertGt(IERC20(ESUSDS).balanceOf(account), 0, "User should have some collateral remaining");
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

    /// @notice Test shrinking the position with partial repayment using EIP-1271
    function test_ClosePositionWrapper_PartialRepay() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 2e18;
        uint256 collateralAmount = SUSDS_MARGIN + 4990e18;
        uint256 sellAmount = 2500e18;
        uint256 buyAmount = 0.98e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params with custom amounts
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);
        params.collateralAmount = sellAmount;
        params.minRepay = 1.5e18; // debt (2e18) - remaining (0.5e18) = 1.5e18 to repay
        params.kind = GPv2Order.KIND_SELL;

        // Get settlement data using EIP-1271
        SettlementData memory settlement = getClosePositionSettlementEIP1271({
            owner: user,
            account: account,
            sellVaultToken: ESUSDS,
            buyToRepayToken: WETH,
            sellAmount: sellAmount,
            buyAmount: 1.5e18,
            userPrivateKey: privateKey,
            isBuy: false
        });

        // Setup approvals
        _setupClosePositionApprovalsFor(user, account, ESUSDS, WETH);

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
            buyAmount,
            0
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
        uint256 collateralAmount = SUSDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ uint8(0x01));

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params using helper
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data
        SettlementData memory settlement = getClosePositionSettlement({
            owner: user,
            account: account,
            sellVaultToken: ESUSDS,
            buyToRepayToken: WETH,
            sellAmount: DEFAULT_SELL_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT
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
            DEFAULT_BUY_REPAID,
            DEFAULT_BUY_LEFTOVER
        );

        // Execute wrapped settlement
        CowWrapper(address(closePositionWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the position was closed successfully
        assertEq(IEVault(EWETH).debtOf(account), 0, "User should have no debt after closing");
        assertEq(debtBefore, borrowAmount, "User should have started with debt");
    }

    /// @notice Test that invalid signature causes the transaction to revert with EIP-1271
    function test_ClosePositionWrapper_InvalidSignatureReverts() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        uint256 borrowAmount = 1e18;
        uint256 collateralAmount = SUSDS_MARGIN + 2495e18;

        address account = address(uint160(user) ^ 1);

        // First, set up a leveraged position
        setupLeveragedPositionFor({
            owner: user,
            account: account,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount,
            borrowAmount: borrowAmount
        });

        // Create params using helper
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _createDefaultParams(user, account);

        // Get settlement data using EIP-1271
        SettlementData memory settlement = getClosePositionSettlementEIP1271({
            owner: user,
            account: account,
            sellVaultToken: ESUSDS,
            buyToRepayToken: WETH,
            sellAmount: DEFAULT_SELL_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT,
            userPrivateKey: privateKey2, // Use wrong private key to create invalid signature
            isBuy: true
        });

        // Setup approvals
        _setupClosePositionApprovalsFor(user, account, ESUSDS, WETH);

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
    /// @dev Two users close positions in the same direction (long SUSDS), one user closes opposite (long WETH)
    function test_ClosePositionWrapper_ThreeUsers_TwoSameOneOpposite() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Configure vault LTVs for both directions
        vm.startPrank(IEVault(ESUSDS).governorAdmin());
        IEVault(ESUSDS).setLTV(EWETH, 0.9e4, 0.9e4, 0);
        vm.stopPrank();

        // Setup accounts
        address account1 = address(uint160(user) ^ 1);
        address account2 = address(uint160(user2) ^ 1);
        address account3 = address(uint160(user3) ^ 1);

        // Setup User1: Long SUSDS (SUSDS collateral, WETH debt). ~1 ETH debt
        setupLeveragedPositionFor({
            owner: user,
            account: account1,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: 3500 ether,
            borrowAmount: 1 ether
        });

        // Setup User2: Long SUSDS (SUSDS collateral, WETH debt). ~3 ETH debt
        setupLeveragedPositionFor({
            owner: user2,
            account: account2,
            collateralVault: ESUSDS,
            borrowVault: EWETH,
            collateralAmount: 10000 ether,
            borrowAmount: 3 ether
        });

        // Setup User3: Long WETH (WETH collateral, SUSDS debt). ~5000 SUSDS debt
        setupLeveragedPositionFor({
            owner: user3,
            account: account3,
            collateralVault: EWETH,
            borrowVault: ESUSDS,
            collateralAmount: 3 ether,
            borrowAmount: 5000 ether
        });

        // Verify positions exist
        assertEq(IEVault(EWETH).debtOf(account1), 1 ether, "User1 should have WETH debt");
        assertEq(IEVault(EWETH).debtOf(account2), 3 ether, "User2 should have WETH debt");
        assertEq(IEVault(ESUSDS).debtOf(account3), 5000 ether, "User3 should have SUSDS debt");

        // Setup approvals for all users
        _setupClosePositionApprovalsFor(user, account1, ESUSDS, WETH);
        _setupClosePositionApprovalsFor(user2, account2, ESUSDS, WETH);
        _setupClosePositionApprovalsFor(user3, account3, EWETH, SUSDS);

        // Create params for all users
        CowEvcClosePositionWrapper.ClosePositionParams memory params1 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user,
            account: account1,
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: ESUSDS,
            collateralAmount: 2550 ether,
            minRepay: 1.001 ether, // full repay of 1 ether debt
            kind: GPv2Order.KIND_BUY,
            appData: bytes32(0)
        });

        CowEvcClosePositionWrapper.ClosePositionParams memory params2 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user2,
            account: account2,
            deadline: block.timestamp + 1 hours,
            borrowVault: EWETH,
            collateralVault: ESUSDS,
            collateralAmount: 7600 ether,
            minRepay: 3.003 ether, // full repay of 3 ether debt
            kind: GPv2Order.KIND_BUY,
            appData: bytes32(0)
        });

        CowEvcClosePositionWrapper.ClosePositionParams memory params3 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: user3,
            account: account3,
            deadline: block.timestamp + 1 hours,
            borrowVault: ESUSDS,
            collateralVault: EWETH,
            collateralAmount: 2.1 ether,
            minRepay: 5005 ether, // full repay of 5000 ether debt
            kind: GPv2Order.KIND_BUY,
            appData: bytes32(0)
        });

        // Create permit signatures for all users
        bytes memory permitSignature1 = _createPermitSignatureFor(params1, privateKey);
        bytes memory permitSignature2 = _createPermitSignatureFor(params2, privateKey2);
        bytes memory permitSignature3 = _createPermitSignatureFor(params3, privateKey3);

        // Create settlement with all three trades using EIP-1271
        uint32 validTo = uint32(block.timestamp + 1 hours);

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

        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](3);
        (trades[0],,) = setupCowOrderEIP1271({
            tokens: tokens,
            sellTokenIndex: 2,
            buyTokenIndex: 1,
            sellAmount: params1.collateralAmount,
            buyAmount: 1.001 ether,
            validTo: validTo,
            signer: user,
            account: account1,
            receiver: closePositionWrapper.getInbox(user, account1),
            isBuy: true,
            signerPrivateKey: privateKey
        });
        (trades[1],,) = setupCowOrderEIP1271({
            tokens: tokens,
            sellTokenIndex: 2,
            buyTokenIndex: 1,
            sellAmount: params2.collateralAmount,
            buyAmount: 3.003 ether,
            validTo: validTo,
            signer: user2,
            account: account2,
            receiver: closePositionWrapper.getInbox(user2, account2),
            isBuy: true,
            signerPrivateKey: privateKey2
        });
        (trades[2],,) = setupCowOrderEIP1271({
            tokens: tokens,
            sellTokenIndex: 3,
            buyTokenIndex: 0,
            sellAmount: params3.collateralAmount,
            buyAmount: 5005 ether,
            validTo: validTo,
            signer: user3,
            account: account3,
            receiver: closePositionWrapper.getInbox(user3, account3),
            isBuy: true,
            signerPrivateKey: privateKey3
        });

        // Setup interactions
        ICowSettlement.Interaction[][3] memory interactions;
        interactions[0] = new ICowSettlement.Interaction[](0);
        interactions[1] = new ICowSettlement.Interaction[](3);
        interactions[2] = new ICowSettlement.Interaction[](0);

        // We pull the money out of the euler vaults
        interactions[1][0] =
            getWithdrawInteraction(ESUSDS, (1.001 ether + 3.003 ether) * clearingPrices[1] / clearingPrices[0]);
        interactions[1][1] = getWithdrawInteraction(EWETH, 5005 ether * clearingPrices[0] / clearingPrices[1]);

        // We swap. We only need to swap the difference of the 3 closes (since coincidence of wants)
        // It comes out to 5000 SUSDS needs to become WETH
        interactions[1][2] = getSwapInteraction(SUSDS, WETH, 5000 ether);

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
        assertEq(IEVault(ESUSDS).debtOf(account3), 0, "User3 should have no SUSDS debt after closing");
    }
}
