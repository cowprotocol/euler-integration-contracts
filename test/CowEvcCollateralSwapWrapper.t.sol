// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcCollateralSwapWrapper} from "../src/CowEvcCollateralSwapWrapper.sol";
import {ICowSettlement, CowWrapper} from "../src/CowWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";

import {CowBaseTest} from "./helpers/CowBaseTest.sol";
import {EvcPermitSigner} from "./helpers/EvcPermitSigner.sol";

import {Constants} from "./helpers/Constants.sol";

/// @title E2E Test for CowEvcCollateralSwapWrapper
/// @notice Tests the full flow of swapping collateral between vaults
contract CowEvcCollateralSwapWrapperTest is CowBaseTest {
    CowEvcCollateralSwapWrapper public collateralSwapWrapper;
    EvcPermitSigner internal ecdsa;

    uint256 constant DEFAULT_SWAP_AMOUNT = 500e18;
    uint256 constant DEFAULT_BUY_AMOUNT = 0.0049e8;

    function setUp() public override {
        super.setUp();

        // Deploy the collateral swap wrapper
        collateralSwapWrapper = new CowEvcCollateralSwapWrapper(address(EVC), COW_SETTLEMENT);
        wrapper = collateralSwapWrapper;

        // Add wrapper as a solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        vm.startPrank(manager);
        allowList.addSolver(address(collateralSwapWrapper));
        vm.stopPrank();

        ecdsa = new EvcPermitSigner(EVC);

        // Setup user with USDS
        deal(address(USDS), user, 10000e18);
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
            fromVault: address(EUSDS),
            toVault: address(EWBTC),
            fromAmount: DEFAULT_SWAP_AMOUNT,
            toAmount: DEFAULT_BUY_AMOUNT
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

    /// @notice Encode collateral swap wrapper data with length prefix
    /// @dev Combines encoding params+signature and adding length prefix
    function _encodeCollateralSwapWrapperData(
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params,
        bytes memory signature
    ) internal pure returns (bytes memory) {
        return encodeWrapperData(abi.encode(params, signature));
    }

    /// @notice Encode settlement data for ICowSettlement.settle call
    function _encodeSettleData(SettlementData memory settlement) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );
    }

    /// @notice Setup user approvals for collateral swap on subaccount
    /// This is only for use on the pre-approved flow, as signatures with permit are used instead with the permit flow.
    function _setupSubaccountAuthorizations(CowEvcCollateralSwapWrapper.CollateralSwapParams memory params) internal {
        vm.startPrank(params.owner);

        // Approve vault shares from main account for settlement
        require(IEVault(params.fromVault).approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max));

        // Set wrapper as operator for the subaccount
        EVC.setAccountOperator(params.account, address(collateralSwapWrapper), true);

        // Pre-approve the operation hash
        bytes32 hash = collateralSwapWrapper.getApprovalHash(params);
        collateralSwapWrapper.setPreApprovedHash(hash, true);

        vm.stopPrank();
    }

    /// @notice Create settlement data for swapping collateral between vaults
    /// @dev Sells vault shares from one vault to buy shares in another
    function prepareCollateralSwapSettlement(
        address owner,
        address account,
        IEVault sellVaultToken,
        IEVault buyVaultToken,
        uint256 sellAmount,
        uint256 buyAmount
    ) public view returns (SettlementData memory r) {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Get tokens and prices
        r.tokens = new address[](2);
        r.tokens[0] = address(sellVaultToken);
        r.tokens[1] = address(buyVaultToken);

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
            receiver: account,
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
        r.interactions[1][1] =
            getSwapInteraction(IERC20(sellVaultToken.asset()), IERC20(buyVaultToken.asset()), sellAmount);

        // Deposit to buy vault (transfer underlying to vault)
        uint256 buyUnderlyingAmount = sellAmount * r.clearingPrices[0] / milkSwap.prices(buyVaultToken.asset());
        r.interactions[1][2] = getDepositInteraction(buyVaultToken, buyUnderlyingAmount);
    }

    /// @notice Parameterized test helper that covers all collateral swap scenarios
    /// @dev This DRY helper eliminates test duplication by consolidating four test cases:
    ///      - Permit + Main Account
    ///      - Permit + Subaccount
    ///      - PreApprove + Main Account
    ///      - PreApprove + Subaccount
    ///
    ///      The helper:
    ///      1. Sets up a leveraged position (1000 USDS collateral, 0.5 WETH debt)
    ///      2. Creates default swap parameters (swap 500 USDS → ~0.0049 WBTC)
    ///      3. Prepares the CoW Protocol settlement with required interactions
    ///      4. Routes to either Permit or PreApprove authorization based on userPrivateKey:
    ///         - Permit flow (userPrivateKey != 0): Creates ECDSA signature on-the-fly
    ///         - PreApprove flow (userPrivateKey == 0): Uses pre-approved hash mechanism
    ///      5. Executes the wrapped settlement through the wrapper
    ///      6. Verifies: correct balance changes + EWBTC collateral enabled
    ///
    /// @param owner The owner/signer of the position
    /// @param account The account that holds the position (owner for main account, different for subaccount)
    /// @param userPrivateKey Private key for permit signature. If set to 0, uses the pre-approved authentication flow
    function _testCollateralSwapFlow(address owner, address account, uint256 userPrivateKey) internal {
        uint256 borrowAmount = 0.5e18; // Borrow 0.5 WETH
        uint256 collateralAmount = 1000e18;

        setupLeveragedPositionFor({
            owner: owner,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount + borrowAmount * 2500,
            borrowAmount: borrowAmount
        });

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(owner, account);

        SettlementData memory settlement = prepareCollateralSwapSettlement({
            owner: owner,
            account: account,
            sellVaultToken: EUSDS,
            buyVaultToken: EWBTC,
            sellAmount: DEFAULT_SWAP_AMOUNT,
            buyAmount: DEFAULT_BUY_AMOUNT
        });

        // Record balances before swap
        uint256 fromVaultBalanceBefore = EUSDS.balanceOf(account);
        uint256 toVaultBalanceBefore = EWBTC.balanceOf(account);

        bytes memory wrapperData;
        bool isPermitFlow = userPrivateKey != 0;

        if (isPermitFlow) {
            // Permit flow: create signature

            bytes memory permitSignature = _createPermitSignatureFor(params, userPrivateKey);
            wrapperData = _encodeCollateralSwapWrapperData(params, permitSignature);

            vm.prank(owner);
            // normally a EIP-712 signature would be created for the CoW order here, but
            // to simplify tests, we use a pre approved hash
            COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);
        } else {
            // PreApprove flow: setup authorizations
            // They are the same whether the subaccount or main account is used
            vm.startPrank(owner);

            // Set wrapper as operator for the subaccount
            EVC.setAccountOperator(params.account, address(collateralSwapWrapper), true);

            // pre approve hash on collateral swap wrapper
            bytes32 hash = collateralSwapWrapper.getApprovalHash(params);
            collateralSwapWrapper.setPreApprovedHash(hash, true);

            // pre approve on CoW setltement order
            COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);
            vm.stopPrank();

            wrapperData = _encodeCollateralSwapWrapperData(params, new bytes(0));
        }

        // The vault relayer contract also needs to be approved so spend funds no matter what case
        vm.startPrank(owner);
        require(EUSDS.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max));
        vm.stopPrank();

        bytes memory settleData = _encodeSettleData(settlement);

        vm.expectEmit();
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.fromAmount, params.toAmount
        );

        CowWrapper(address(collateralSwapWrapper)).wrappedSettle(settleData, wrapperData);

        // Verify the collateral was swapped successfully
        assertEq(
            EUSDS.balanceOf(account),
            fromVaultBalanceBefore - DEFAULT_SWAP_AMOUNT,
            "Account should have less EUSDS after swap"
        );
        assertApproxEqAbs(
            EWBTC.balanceOf(account), toVaultBalanceBefore + DEFAULT_BUY_AMOUNT, 1, "Account should have received EWBTC"
        );

        // Verify the new collateral vault is enabled
        assertTrue(EVC.isCollateralEnabled(account, address(EWBTC)), "EWBTC vault should be enabled");

        // Operator authorizations should have been revoked (only actually used by pre-approve flow)
        assertFalse(
            EVC.isAccountOperatorAuthorized(owner, address(collateralSwapWrapper)),
            "Wrapper should not be operator after settlement"
        );
        assertFalse(
            EVC.isAccountOperatorAuthorized(account, address(collateralSwapWrapper)),
            "Wrapper should not be operator after settlement"
        );
        assertFalse(
            EVC.isAccountOperatorAuthorized(owner, address(collateralSwapWrapper)),
            "Wrapper should not be operator for the owner after settlement"
        );
        assertFalse(
            EVC.isAccountOperatorAuthorized(account, address(collateralSwapWrapper)),
            "Wrapper should not be operator for the subaccount after settlement"
        );
    }

    function test_CollateralSwapWrapper_Permit_MainAccount() external {
        _testCollateralSwapFlow(user, user, privateKey);
    }

    function test_CollateralSwapWrapper_Permit_Subaccount() external {
        _testCollateralSwapFlow(user, account, privateKey);
    }

    function test_CollateralSwapWrapper_PreApprove_MainAccount() external {
        _testCollateralSwapFlow(user, user, 0);
    }

    function test_CollateralSwapWrapper_PreApprove_Subaccount() external {
        _testCollateralSwapFlow(user, account, 0);
    }

    /// @notice Test that invalid signature causes the transaction to revert
    function test_CollateralSwapWrapper_InvalidSignatureReverts() external {
        uint256 borrowAmount = 0.5e18; // Borrow 0.5 WETH
        uint256 collateralAmount = 2000e18;

        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: user,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount + borrowAmount * 2500e18 / 0.99e18,
            borrowAmount: borrowAmount
        });

        // Create params using helper (use user as both owner and account to avoid subaccount transfers)
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(user, user);

        vm.prank(user);
        require(EUSDS.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max));

        // Create INVALID permit signature by signing with wrong private key (user2's key instead of user's)
        ecdsa.setPrivateKey(privateKey2);
        bytes memory invalidPermitSignature = ecdsa.signPermit(
            params.owner,
            address(collateralSwapWrapper),
            uint256(uint160(address(collateralSwapWrapper))),
            0,
            params.deadline,
            0,
            collateralSwapWrapper.encodePermitData(params)
        );

        // Encode empty settlement and some wrapper data
        SettlementData memory settlement;
        bytes memory settleData = _encodeSettleData(settlement);
        bytes memory wrapperData = _encodeCollateralSwapWrapperData(params, invalidPermitSignature);

        // Execute wrapped settlement - should revert with EVC_NotAuthorized due to invalid signature
        vm.expectRevert(abi.encodeWithSignature("EVC_NotAuthorized()"));
        CowWrapper(address(collateralSwapWrapper)).wrappedSettle(settleData, wrapperData);
    }

    /// @notice Test that the wrapper can handle being called three times in the same chain
    /// @dev Two users swap USDS→WETH, one user swaps WETH→USDS
    /// User1+User2 swap eUSDS→eWETH (sell 700 + 300 = 1000 eUSDS, need 0.2 + 0.2 = 0.4 eWETH), User3 swaps eWETH→eUSDS (sell 0.8 eWETH, needs 2000 eUSDS).
    /// Coincidence of wants: User3 provides 0.8 eWETH, User1+User2 need 0.4 eWETH → surplus of 0.4 eWETH. User1+User2 provide 1000 eUSDS, User3 needs 2000 eUSDS → deficit of 1000 eUSDS.
    /// We withdraw 0.4 WETH from vault, swap to 1000 USDS (at rate 2500 USD/ETH), and deposit into eUSDS vault to cover the deficit and balance the trades.
    function test_CollateralSwapWrapper_ThreeUsers_TwoSameOneOpposite() external {
        // Set WETH as good collateral to allow user3 to use it as collateral
        vm.startPrank(EWBTC.governorAdmin());
        EWBTC.setLTV(address(EWETH), EWBTC.LTVBorrow(address(EUSDS)), EWBTC.LTVBorrow(address(EUSDS)), 0);
        vm.stopPrank();

        // Setup User1: Long USDS (USDS collateral, WBTC debt). 0.02 WBTC debt
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWBTC,
            collateralAmount: 3000 ether,
            borrowAmount: 0.02e8
        });

        // Setup User2: Long USDS (USDS collateral, WBTC debt). 0.06 WBTC debt
        setupLeveragedPositionFor({
            owner: user2,
            ownerAccount: account2,
            collateralVault: EUSDS,
            borrowVault: EWBTC,
            collateralAmount: 9000 ether,
            borrowAmount: 0.06e8
        });

        // Setup User3: Long WETH (WETH collateral, WBTC debt). 0.03 WBTC debt
        setupLeveragedPositionFor({
            owner: user3,
            ownerAccount: account3,
            collateralVault: EWETH,
            borrowVault: EWBTC,
            collateralAmount: 2 ether,
            borrowAmount: 0.03e8
        });

        // Verify positions exist
        assertEq(EWBTC.debtOf(account), 0.02e8, "Account 1 should have WBTC debt");
        assertEq(EWBTC.debtOf(account2), 0.06e8, "Account 2 should have WBTC debt");
        assertEq(EWBTC.debtOf(account3), 0.03e8, "Account 3 should have WBTC debt");

        // Verify collaterals
        assertEq(
            EUSDS.convertToAssets(EUSDS.balanceOf(account)),
            3000 ether - 1,
            //Constants.ONE_PERCENT,
            "Account 1 should have USDS collateral"
        );
        assertEq(
            EUSDS.convertToAssets(EUSDS.balanceOf(account2)),
            9000 ether - 1,
            //Constants.ONE_PERCENT,
            "Account 2 should have USDS collateral"
        );
        assertEq(
            EWETH.convertToAssets(EWETH.balanceOf(account3)),
            2 ether - 1,
            //Constants.ONE_PERCENT,
            "Account 3 should have WETH collateral"
        );

        // Create params for all users
        // 1 ETH = 2500 USDS
        // We give a little room for slippage becuase the deposit/withdraw functions for Euler wrapped tokens are "almost" 1:1, so
        // some reduced/increased tokens can happen due to token withdraw/desposit on Euler vaults.
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params1 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user,
                account: account,
                deadline: block.timestamp + 1 hours,
                fromVault: address(EUSDS),
                toVault: address(EWETH),
                fromAmount: EUSDS.convertToShares(300 ether),
                toAmount: 0.118 ether
            });

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params2 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user2,
                account: account2,
                deadline: block.timestamp + 1 hours,
                fromVault: address(EUSDS),
                toVault: address(EWETH),
                fromAmount: EUSDS.convertToShares(700 ether),
                toAmount: EWETH.convertToShares(0.278 ether)
            });

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params3 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user3,
                account: account3,
                deadline: block.timestamp + 1 hours,
                fromVault: address(EWETH),
                toVault: address(EUSDS),
                fromAmount: EWETH.convertToShares(0.8 ether),
                toAmount: EUSDS.convertToShares(1950 ether)
            });

        // Create permit signatures for all users
        bytes memory permitSignature1 = _createPermitSignatureFor(params1, privateKey);
        bytes memory permitSignature2 = _createPermitSignatureFor(params2, privateKey2);
        bytes memory permitSignature3 = _createPermitSignatureFor(params3, privateKey3);

        // Create settlement with all three trades
        uint32 validTo = uint32(block.timestamp + 1 hours);

        (address[] memory tokens, uint256[] memory clearingPrices) = getTokensAndPrices();

        SettlementData memory settlement;
        settlement.tokens = tokens;
        settlement.clearingPrices = clearingPrices;

        settlement.trades = new ICowSettlement.Trade[](3);
        bytes[] memory orderIds = new bytes[](3);
        (settlement.trades[0],, orderIds[0]) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 2, // eUSDS
            buyTokenIndex: 3, // eWETH
            sellAmount: params1.fromAmount,
            buyAmount: params1.toAmount,
            validTo: validTo,
            owner: user,
            receiver: account,
            isBuy: false
        });
        (settlement.trades[1],, orderIds[1]) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 2, // eUSDS
            buyTokenIndex: 3, // eWETH
            sellAmount: params2.fromAmount,
            buyAmount: params2.toAmount,
            validTo: validTo,
            owner: user2,
            receiver: account2,
            isBuy: false
        });
        (settlement.trades[2],, orderIds[2]) = setupCowOrder({
            tokens: tokens,
            sellTokenIndex: 3, // eWETH
            buyTokenIndex: 2, // eUSDS
            sellAmount: params3.fromAmount,
            buyAmount: params3.toAmount,
            validTo: validTo,
            owner: user3,
            receiver: account3,
            isBuy: false
        });

        // Setup interactions
        settlement.interactions[0] = new ICowSettlement.Interaction[](0);
        settlement.interactions[1] = new ICowSettlement.Interaction[](3);
        settlement.interactions[2] = new ICowSettlement.Interaction[](0);

        // We pull the money out of the euler vaults
        settlement.interactions[1][0] = getWithdrawInteraction(EWETH, 0.4 ether);

        // We swap all of the WETH we need
        settlement.interactions[1][1] = getSwapInteraction(WETH, USDS, 0.4 ether);

        // We deposit back into USDS vault
        settlement.interactions[1][2] = getDepositInteraction(EUSDS, 1000 ether);

        // Encode settlement data
        bytes memory settleData = _encodeSettleData(settlement);

        // Chain wrapper data
        bytes[] memory wrapperDatas = new bytes[](3);
        wrapperDatas[0] = abi.encode(params1, permitSignature1);
        wrapperDatas[1] = abi.encode(params2, permitSignature2);
        wrapperDatas[2] = abi.encode(params3, permitSignature3);

        bytes memory wrapperData = abi.encodePacked(
            uint16(wrapperDatas[0].length),
            wrapperDatas[0],
            address(collateralSwapWrapper),
            uint16(wrapperDatas[1].length),
            wrapperDatas[1],
            address(collateralSwapWrapper),
            uint16(wrapperDatas[2].length),
            wrapperDatas[2]
        );

        // Setup approvals for all users
        _setupSubaccountAuthorizations(params1);
        _setupSubaccountAuthorizations(params2);
        _setupSubaccountAuthorizations(params3);

        // CoW order should be authorized too
        vm.prank(user);
        COW_SETTLEMENT.setPreSignature(orderIds[0], true);
        vm.prank(user2);
        COW_SETTLEMENT.setPreSignature(orderIds[1], true);
        vm.prank(user3);
        COW_SETTLEMENT.setPreSignature(orderIds[2], true);

        // Execute wrapped settlement
        collateralSwapWrapper.wrappedSettle(settleData, wrapperData);

        // Verify all positions remaing the same in terms of debt
        assertEq(EWBTC.debtOf(account), 0.02e8, "Account 1 should have WBTC debt");
        assertEq(EWBTC.debtOf(account2), 0.06e8, "Account 2 should have WBTC debt");
        assertEq(EWBTC.debtOf(account3), 0.03e8, "Account 3 should have WBTC debt");

        // Verify original collaterals
        assertEq(EUSDS.convertToAssets(EUSDS.balanceOf(account)), 2700 ether, "Account 1 should have USDS collateral");
        assertEq(EUSDS.convertToAssets(EUSDS.balanceOf(account2)), 8300 ether, "Account 2 should have USDS collateral");
        assertEq(
            EWETH.convertToAssets(EWETH.balanceOf(account3)), 1.2 ether - 1, "Account 3 should have WETH collateral"
        );

        // Verify new collaterals
        // account 1 is the only type=SELL order. It sold exactly
        assertEq(
            EWETH.convertToAssets(EWETH.balanceOf(account)), 0.12 ether, "Account 1 should have some WETH collateral"
        );
        assertEq(
            EWETH.convertToAssets(EWETH.balanceOf(account2)), 0.28 ether, "Account 2 should have some WETH collateral"
        );
        assertApproxEqRel(
            EUSDS.convertToAssets(EUSDS.balanceOf(account3)),
            2000 ether - 1,
            Constants.ONE_PERCENT,
            "Account 3 should have some USDS collateral"
        );
    }
}
