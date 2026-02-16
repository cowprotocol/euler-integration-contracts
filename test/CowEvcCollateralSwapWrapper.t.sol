// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

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

        ecdsa = new SignerECDSA(EVC);

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
        uint256 swapAmount = sellAmount * 0.999 ether / 1 ether;
        r.interactions[1][1] =
            getSwapInteraction(IERC20(sellVaultToken.asset()), IERC20(buyVaultToken.asset()), swapAmount);

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
    ///      5. For PreApprove, further branches on owner==account:
    ///         - Main account: Inline setup (approve + set hash + set operator)
    ///         - Subaccount: Uses _setupSubaccountAuthorizations helper
    ///      6. Executes the wrapped settlement through the wrapper
    ///      7. Verifies: correct balance changes + EWBTC collateral enabled
    ///
    /// @param owner The owner/signer of the position
    /// @param account The account that holds the position (owner for main account, different for subaccount)
    /// @param userPrivateKey Private key for permit signature. If set to 0, uses the pre-approved authentication flow
    function _testCollateralSwapFlow(address owner, address account, uint256 userPrivateKey) internal {
        uint256 borrowAmount = 0.5e18; // Borrow 0.5 WETH
        uint256 collateralAmount = 1000e18;

        // Set up a leveraged position
        setupLeveragedPositionFor({
            owner: owner,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: collateralAmount + borrowAmount * 2500e18 / 0.99e18,
            borrowAmount: borrowAmount
        });

        // Create params
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _createDefaultParams(owner, account);

        // Get settlement data
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

        // Setup authorization and encode wrapper data
        bytes memory wrapperData;
        bool isPermitFlow = userPrivateKey != 0;

        if (isPermitFlow) {
            // Permit flow: create signature

            bytes memory permitSignature = _createPermitSignatureFor(params, userPrivateKey);
            wrapperData = _encodeWrapperData(params, permitSignature);

            vm.startPrank(owner);
            // The vault relayer contract also needs to be approved so spend funds
            require(EUSDS.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max));

            // normally a EIP-712 signature would be created for the CoW order here, but
            // to simplify tests, we use a pre approved hash
            COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);
            vm.stopPrank();
        } else {
            // PreApprove flow: setup authorizations
            if (owner == account) {
                // Main account: inline setup (less calls are needed)
                vm.startPrank(owner);
                require(EUSDS.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max));
                bytes32 hash = collateralSwapWrapper.getApprovalHash(params);
                collateralSwapWrapper.setPreApprovedHash(hash, true);
                EVC.setAccountOperator(params.account, address(collateralSwapWrapper), true);
                vm.stopPrank();
            } else {
                // Subaccount: use helper shared by other tests
                _setupSubaccountAuthorizations(params);
            }

            vm.prank(owner);
            COW_SETTLEMENT.setPreSignature(settlement.orderUid, true);

            wrapperData = _encodeWrapperData(params, new bytes(0));
        }

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );

        // Expect event emission
        vm.expectEmit();
        emit CowEvcCollateralSwapWrapper.CowEvcCollateralSwapped(
            params.owner, params.account, params.fromVault, params.toVault, params.fromAmount, params.toAmount
        );

        // Execute wrapped settlement
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

        assertFalse(EVC.isAccountOperatorAuthorized(owner, address(collateralSwapWrapper)), "Wrapper should not be operator after settlement");
        assertFalse(EVC.isAccountOperatorAuthorized(account, address(collateralSwapWrapper)), "Wrapper should not be operator after settlement");
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

        // Set up a leveraged position
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

        // Get settlement data
        SettlementData memory settlement;
        {
            uint32 validTo = uint32(block.timestamp + 1 hours);

            // Get tokens and prices
            settlement.tokens = new address[](2);
            settlement.tokens[0] = address(EUSDS);
            settlement.tokens[1] = address(WBTC);

            settlement.clearingPrices = new uint256[](2);
            settlement.clearingPrices[0] = milkSwap.prices(IERC4626(EUSDS).asset());
            settlement.clearingPrices[1] = milkSwap.prices(address(WBTC)) * 1 ether / 0.98 ether;

            // Get trade data
            settlement.trades = new ICowSettlement.Trade[](1);
            (settlement.trades[0], settlement.orderData, settlement.orderUid) = setupCowOrder({
                tokens: settlement.tokens,
                sellTokenIndex: 0,
                buyTokenIndex: 1,
                sellAmount: params.fromAmount,
                buyAmount: params.toAmount,
                validTo: validTo,
                owner: params.owner,
                receiver: params.account,
                isBuy: false
            });

            // Setup interactions - withdraw from sell vault, swap underlying assets, deposit to buy vault
            settlement.interactions = [
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](2),
                new ICowSettlement.Interaction[](0)
            ];

            // Withdraw from sell vault
            settlement.interactions[1][0] = getWithdrawInteraction(EUSDS, params.fromAmount);

            // Swap underlying assets
            uint256 swapAmount = params.fromAmount * 0.999 ether / 1 ether;
            settlement.interactions[1][1] = getSwapInteraction(IERC20(EUSDS.asset()), WBTC, swapAmount);
        }

        // Approve vault shares for settlement
        vm.prank(user);
        require(EUSDS.approve(COW_SETTLEMENT.vaultRelayer(), type(uint256).max));

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

    /// @notice Test that the wrapper can handle being called three times in the same chain
    /// @dev Two users close positions in the same direction (long USDS), one user closes opposite (long WETH)
    function test_CollateralSwapWrapper_ThreeUsers_TwoSameOneOpposite() external {
        vm.skip(bytes(forkRpcUrl).length == 0);

        // Setup User1: Long USDS (USDS collateral, WETH debt). 1 ETH debt
        setupLeveragedPositionFor({
            owner: user,
            ownerAccount: account,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 3750 ether,
            borrowAmount: 1 ether
        });

        // Setup User2: Long USDS (USDS collateral, WETH debt). 3 ETH debt
        setupLeveragedPositionFor({
            owner: user2,
            ownerAccount: account2,
            collateralVault: EUSDS,
            borrowVault: EWETH,
            collateralAmount: 12500 ether,
            borrowAmount: 3 ether
        });

        // Setup User3: Long WBTC (WETH collateral, WBTC debt). 2 ETH debt
        setupLeveragedPositionFor({
            owner: user3,
            ownerAccount: account3,
            collateralVault: EWBTC,
            borrowVault: EWETH,
            collateralAmount: 0.075e8,
            borrowAmount: 2 ether
        });

        // Verify positions exist
        assertEq(EWETH.debtOf(account), 1 ether, "Account 1 should have WETH debt");
        assertEq(EWETH.debtOf(account2), 3 ether, "Account 2 should have WETH debt");
        assertEq(EWETH.debtOf(account3), 2 ether, "Account 3 should have WETH debt");

        // Verify collaterals
        assertApproxEqRel(
            EUSDS.convertToAssets(EUSDS.balanceOf(account)),
            3750 ether,
            0.01 ether,
            "Account 1 should have USDS collateral"
        );
        assertApproxEqRel(
            EUSDS.convertToAssets(EUSDS.balanceOf(account2)),
            12500 ether,
            0.01 ether,
            "Account 2 should have USDS collateral"
        );
        assertApproxEqRel(
            EWBTC.convertToAssets(EWBTC.balanceOf(account3)),
            0.075e8,
            0.01 ether,
            "Account 3 should have WBTC collateral"
        );

        // Create params for all users
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params1 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user,
                account: account,
                deadline: block.timestamp + 1 hours,
                fromVault: address(EUSDS),
                toVault: address(EWBTC),
                fromAmount: 500 ether,
                toAmount: 0.0045e8
            });

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params2 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user2,
                account: account2,
                deadline: block.timestamp + 1 hours,
                fromVault: address(EUSDS),
                toVault: address(EWBTC),
                fromAmount: 550 ether,
                toAmount: 0.005e8 // about 500 EUSDS
            });

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params3 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: user3,
                account: account3,
                deadline: block.timestamp + 1 hours,
                fromVault: address(EWBTC),
                toVault: address(EUSDS),
                fromAmount: 0.025e8, // will be calculated from toAmount
                toAmount: 2000 ether
            });

        // Create permit signatures for all users
        bytes memory permitSignature1 = _createPermitSignatureFor(params1, privateKey);
        bytes memory permitSignature2 = _createPermitSignatureFor(params2, privateKey2);
        bytes memory permitSignature3 = _createPermitSignatureFor(params3, privateKey3);

        // Create settlement with all three trades
        uint32 validTo = uint32(block.timestamp + 1 hours);

        SettlementData memory settlement;

        settlement.tokens = new address[](2);
        settlement.tokens[0] = address(EUSDS);
        settlement.tokens[1] = address(EWBTC);

        settlement.clearingPrices = new uint256[](2);
        settlement.clearingPrices[0] = 1 ether; // eUSDS price
        settlement.clearingPrices[1] = 100000 ether * 1e10; // eWBTC price

        settlement.trades = new ICowSettlement.Trade[](3);
        bytes[] memory orderIds = new bytes[](3);
        (settlement.trades[0],, orderIds[0]) = setupCowOrder({
            tokens: settlement.tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: params1.fromAmount,
            buyAmount: params1.toAmount,
            validTo: validTo,
            owner: user,
            receiver: account,
            isBuy: false
        });
        (settlement.trades[1],, orderIds[1]) = setupCowOrder({
            tokens: settlement.tokens,
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            sellAmount: params2.fromAmount,
            buyAmount: params2.toAmount,
            validTo: validTo,
            owner: user2,
            receiver: account2,
            isBuy: true
        });
        (settlement.trades[2],, orderIds[2]) = setupCowOrder({
            tokens: settlement.tokens,
            sellTokenIndex: 1,
            buyTokenIndex: 0,
            sellAmount: params3.fromAmount,
            buyAmount: params3.toAmount,
            validTo: validTo,
            owner: user3,
            receiver: account3,
            isBuy: true
        });

        // Setup interactions
        settlement.interactions[0] = new ICowSettlement.Interaction[](0);
        settlement.interactions[1] = new ICowSettlement.Interaction[](3);
        settlement.interactions[2] = new ICowSettlement.Interaction[](0);

        // We pull the money out of the euler vaults
        settlement.interactions[1][0] = getWithdrawInteraction(EWBTC, 0.01e8);

        // We swap all of the WBTC we need
        settlement.interactions[1][1] = getSwapInteraction(WBTC, USDS, 0.01e8);

        // We deposit back into WBTC
        settlement.interactions[1][2] = getDepositInteraction(EUSDS, 1000 ether);

        // Encode settlement data
        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions)
        );

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

        // Verify all positions closed successfully
        assertEq(EWETH.debtOf(account), 1 ether, "User1 should have WETH debt");
        assertEq(EWETH.debtOf(account2), 3 ether, "User2 should have WETH debt");
        assertEq(EWETH.debtOf(account3), 2 ether, "User3 should have WETH debt");

        // Verify original collaterals
        assertApproxEqRel(
            IERC4626(EUSDS).convertToAssets(EUSDS.balanceOf(account)),
            3250 ether,
            0.01 ether,
            "Account 1 should have less USDS collateral"
        );
        assertApproxEqRel(
            IERC4626(EUSDS).convertToAssets(EUSDS.balanceOf(account2)),
            12000 ether,
            0.01 ether,
            "Account 2 should have less USDS collateral"
        );
        assertApproxEqRel(EWBTC.balanceOf(account3), 0.05e8, 0.01 ether, "Account 3 should have less WBTC collateral");

        // Verify new collaterals
        assertApproxEqRel(EWBTC.balanceOf(account), 0.005e8, 0.01 ether, "Account 1 should have some WBTC collateral");
        assertEq(EWBTC.balanceOf(account2), 0.005e8, "Account 2 should have some WBTC collateral");
        assertEq(EUSDS.balanceOf(account3), 2000 ether, "Account 3 should have some USDS collateral");
    }
}
