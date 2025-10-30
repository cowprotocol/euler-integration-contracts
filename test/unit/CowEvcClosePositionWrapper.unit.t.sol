// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import "forge-std/Test.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcClosePositionWrapper} from "../../src/CowEvcClosePositionWrapper.sol";
import {CowSettlement, CowAuthentication} from "../../src/vendor/CowWrapper.sol";
import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";
import {MockERC20, MockVault, MockBorrowVault} from "./mocks/MockERC20AndVaults.sol";

/// @title Unit tests for CowEvcClosePositionWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcClosePositionWrapperUnitTest is Test {
    CowEvcClosePositionWrapper public wrapper;
    MockEVC public mockEVC;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;
    MockERC20 public mockAsset;
    MockVault public mockCollateralVault;
    MockBorrowVault public mockBorrowVault;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address constant SOLVER = address(0x3333);

    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    // Helper function to decode signed calldata
    function _decodeSignedCalldata(bytes memory signedCalldata) internal pure returns (IEVC.BatchItem[] memory) {
        bytes memory encodedItems = new bytes(signedCalldata.length - 4);
        for (uint256 i = 4; i < signedCalldata.length; i++) {
            encodedItems[i - 4] = signedCalldata[i];
        }
        return abi.decode(encodedItems, (IEVC.BatchItem[]));
    }

    function setUp() public {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEVC = new MockEVC();
        mockAsset = new MockERC20("Mock Asset", "MOCK");
        mockCollateralVault = new MockVault(address(mockAsset), "Mock Collateral", "mCOL");
        mockBorrowVault = new MockBorrowVault(address(mockAsset), "Mock Borrow", "mBOR");

        wrapper = new CowEvcClosePositionWrapper(address(mockEVC), CowSettlement(address(mockSettlement)));

        // Set solver as authenticated
        mockAuth.setSolver(SOLVER, true);

        // Set the correct onBehalfOfAccount for evcInternalSettle calls
        mockEVC.setOnBehalfOf(address(wrapper));
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(wrapper.EVC()), address(mockEVC), "EVC not set correctly");
        assertEq(address(wrapper.SETTLEMENT()), address(mockSettlement), "SETTLEMENT not set correctly");
        assertEq(address(wrapper.AUTHENTICATOR()), address(mockAuth), "AUTHENTICATOR not set correctly");
        assertEq(wrapper.NONCE_NAMESPACE(), uint256(uint160(address(wrapper))), "NONCE_NAMESPACE incorrect");
    }

    function test_Constructor_SetsDomainSeparator() public view {
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("CowEvcClosePositionWrapper"),
                keccak256("1"),
                block.chainid,
                address(wrapper)
            )
        );
        assertEq(wrapper.DOMAIN_SEPARATOR(), expectedDomainSeparator, "DOMAIN_SEPARATOR incorrect");
    }

    function test_Constructor_SetsName() public view {
        assertEq(wrapper.name(), "Euler EVC - Close Position", "Name not set correctly");
    }

    /*//////////////////////////////////////////////////////////////
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ParseWrapperData_EmptySignature() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithSignature() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signature = new bytes(65);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithExtraData() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signature = new bytes(0);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory extraData = hex"deadbeef";
        wrapperData = abi.encodePacked(wrapperData, extraData);

        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 4, "Should have 4 bytes remaining");
        assertEq(remaining, extraData, "Extra data should match");
    }

    /*//////////////////////////////////////////////////////////////
                    APPROVAL HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetApprovalHash_Consistency() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes32 hash1 = wrapper.getApprovalHash(params);
        bytes32 hash2 = wrapper.getApprovalHash(params);

        assertEq(hash1, hash2, "Hash should be consistent");
    }

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params1 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        // Same as params1 except owner
        CowEvcClosePositionWrapper.ClosePositionParams memory params2 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: ACCOUNT,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        // Same as params1 except repayAmount (the last) field
        CowEvcClosePositionWrapper.ClosePositionParams memory params3 = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 2000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes32 hash1 = wrapper.getApprovalHash(params1);
        bytes32 hash2 = wrapper.getApprovalHash(params2);
        bytes32 hash3 = wrapper.getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    function test_GetApprovalHash_MatchesEIP712() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes32 structHash = keccak256(
            abi.encode(
                params.owner,
                params.account,
                params.deadline,
                params.borrowVault,
                params.collateralVault,
                params.collateralAmount,
                params.repayAmount,
                params.kind
            )
        );

        bytes32 expectedDigest = keccak256(abi.encodePacked("\x19\x01", wrapper.DOMAIN_SEPARATOR(), structHash));
        bytes32 actualDigest = wrapper.getApprovalHash(params);

        assertEq(actualDigest, expectedDigest, "Hash should match EIP-712 format");
    }

    /*//////////////////////////////////////////////////////////////
                    GET SIGNED CALLDATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetSignedCalldata_FullRepay() public {
        // Set up a debt scenario
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18, // Exactly matches debt
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items.length, 1, "Should have 1 batch item");
    }

    function test_GetSignedCalldata_PartialRepay() public {
        // Set up a debt scenario
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 500e18, // Less than debt
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items.length, 1, "Should have 1 batch item for partial repay");
    }

    function test_GetSignedCalldata_RepayItem() public {
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[0].targetContract, address(wrapper), "First item should target wrapper");
        assertEq(items[0].onBehalfOfAccount, ACCOUNT, "Should call on behalf of account");
        assertEq(
            items[0].data,
            abi.encodeCall(wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT)),
            "Should call helperRepay"
        );
    }

    function test_GetSignedCalldata_ContainsRepayItem() public {
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[0].targetContract, address(wrapper), "Item should target wrapper");
        assertEq(items[0].onBehalfOfAccount, ACCOUNT, "Should operate on behalf of account");
    }

    /*//////////////////////////////////////////////////////////////
                    HELPER REPAY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_HelperRepay_SuccessfulRepay() public {
        // Give wrapper some tokens
        mockAsset.mint(address(wrapper), 1000e18);

        // Set up borrow vault with debt
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockBorrowVault.setRepayAmount(1000e18);

        // Make user an operator
        mockEVC.setOperator(ACCOUNT, address(wrapper), true);

        // Call through EVC batch
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(
                wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT)
            )
        });

        vm.prank(address(wrapper));
        mockEVC.batch(items);

        // Verify no tokens left in wrapper (all repaid)
        assertEq(mockAsset.balanceOf(address(wrapper)), 0, "Wrapper should have no tokens left");
    }

    function test_HelperRepay_WithDust() public {
        // Give wrapper more tokens than needed for repay
        mockAsset.mint(address(wrapper), 1100e18);

        // Set up borrow vault with debt
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockBorrowVault.setRepayAmount(1000e18); // Only 1000 actually needed

        mockEVC.setOperator(ACCOUNT, address(wrapper), true);

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(
                wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT)
            )
        });

        vm.prank(address(wrapper));
        mockEVC.batch(items);

        // Wrapper should have no tokens left - they were all used for repay or sent to owner
        assertEq(mockAsset.balanceOf(address(wrapper)), 0, "Wrapper should have no tokens left");
    }

    function test_HelperRepay_InsufficientBalance() public {
        // Give wrapper insufficient tokens
        mockAsset.mint(address(wrapper), 500e18);

        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockEVC.setOperator(ACCOUNT, address(wrapper), true);

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(
                wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT)
            )
        });

        vm.prank(address(wrapper));
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcClosePositionWrapper.InsufficientRepaymentAsset.selector,
                address(mockBorrowVault),
                500e18,
                1000e18
            )
        );
        mockEVC.batch(items);
    }

    function test_HelperRepay_RepayAll() public {
        mockAsset.mint(address(wrapper), 1100e18);
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockBorrowVault.setRepayAmount(1000e18);

        mockEVC.setOperator(ACCOUNT, address(wrapper), true);

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(
                wrapper.helperRepay,
                (address(mockBorrowVault), OWNER, ACCOUNT)
            )
        });

        vm.prank(address(wrapper));
        mockEVC.batch(items);

        // Dust should be returned to owner
        assertGt(mockAsset.balanceOf(OWNER), 0, "Owner should receive dust");
    }

    /*//////////////////////////////////////////////////////////////
                    EVC INTERNAL SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EvcInternalSettle_OnlyEVC() public {
        bytes memory settleData = "";
        bytes memory wrapperData = "";
        bytes memory remainingWrapperData = "";

        vm.expectRevert(abi.encodeWithSelector(CowEvcClosePositionWrapper.Unauthorized.selector, address(this)));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSettle_RequiresCorrectOnBehalfOfAccount() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        // Set incorrect onBehalfOfAccount (not address(wrapper))
        mockEVC.setOnBehalfOf(address(0x9999));

        vm.prank(address(mockEVC));
        vm.expectRevert(abi.encodeWithSelector(CowEvcClosePositionWrapper.Unauthorized.selector, address(0x9999)));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSettle_CanBeCalledByEVC() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: OWNER, // Same account, no transfer needed
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSettle_WithSubaccountTransfer() public {
        // Set up scenario where owner != account
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT, // Different from owner
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 1000e18,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        // Give account some collateral vault tokens
        mockCollateralVault.mint(ACCOUNT, 2000e18);

        // These tokens need to be spendable by the wrapper
        vm.prank(ACCOUNT);
        mockCollateralVault.approve(address(wrapper), 2000e18);

        // Create settle data with tokens and prices
        address[] memory tokens = new address[](2);
        tokens[0] = address(mockCollateralVault);
        tokens[1] = address(mockAsset);

        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18; // 1:1 price for simplicity
        prices[1] = 1e18;

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);

        // Verify transfer occurred from account to owner
        assertLt(mockCollateralVault.balanceOf(ACCOUNT), 2000e18, "Account balance should decrease");
        assertGt(mockCollateralVault.balanceOf(OWNER), 0, "Owner should receive tokens");
    }

    function test_EvcInternalSettle_PricesNotFoundReverts() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        // Create settle data with empty tokens (should fail to find prices)
        address[] memory tokens = new address[](0);
        uint256[] memory prices = new uint256[](0);

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcClosePositionWrapper.PricesNotFoundInSettlement.selector,
                mockCollateralVault,
                mockBorrowVault.asset()
            )
        );
        vm.prank(address(mockEVC));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSettle_SubaccountMustBeControlledByOwner() public {
        // Create an account that is NOT a valid subaccount of the owner
        // Valid subaccount would share first 19 bytes, but this one doesn't
        address invalidSubaccount = address(0x9999999999999999999999999999999999999999);

        // Approve the wrapper to transfer from the subaccount (in case it succeeds)
        vm.prank(invalidSubaccount);
        mockCollateralVault.approve(address(wrapper), type(uint256).max);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: invalidSubaccount, // Invalid subaccount
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 1000e18,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        // Give account some collateral vault tokens
        mockCollateralVault.mint(invalidSubaccount, 2000e18);

        // Create settle data with tokens and prices
        address[] memory tokens = new address[](2);
        tokens[0] = address(mockCollateralVault);
        tokens[1] = address(mockAsset);

        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18;
        prices[1] = 1e18;

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcClosePositionWrapper.SubaccountMustBeControlledByOwner.selector, invalidSubaccount, OWNER
            )
        );
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WrappedSettle_OnlySolver() public {
        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        vm.expectRevert(abi.encodeWithSignature("NotASolver(address)", address(this)));
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPermitSignature() public {
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        mockCollateralVault.mint(ACCOUNT, 2000e18);

        MockERC20(mockBorrowVault.asset()).mint(address(wrapper), 1000e18);

        // These tokens need to be spendable by the wrapper
        vm.prank(ACCOUNT);
        mockCollateralVault.approve(address(wrapper), 2000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        address[] memory tokens = new address[](2);
        tokens[0] = mockBorrowVault.asset();
        tokens[1] = address(mockCollateralVault);
        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18;
        prices[1] = 1e18;

        bytes memory signature = new bytes(65);
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        mockCollateralVault.mint(ACCOUNT, 2000e18);

        MockERC20(mockBorrowVault.asset()).mint(address(wrapper), 1000e18);

        // These tokens need to be spendable by the wrapper
        vm.prank(ACCOUNT);
        mockCollateralVault.approve(address(wrapper), 2000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        mockEVC.setOperator(OWNER, address(wrapper), true);
        mockEVC.setOperator(ACCOUNT, address(wrapper), true);

        address[] memory tokens = new address[](2);
        tokens[0] = mockBorrowVault.asset();
        tokens[1] = address(mockCollateralVault);
        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18;
        prices[1] = 1e18;

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_PreApprovedHashRevertsIfDeadlineExceeded() public {
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp - 1, // Past deadline
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        mockEVC.setOperator(OWNER, address(wrapper), true);
        mockEVC.setOperator(ACCOUNT, address(wrapper), true);

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        vm.prank(SOLVER);
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcClosePositionWrapper.OperationDeadlineExceeded.selector, params.deadline, block.timestamp
            )
        );
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_MaxRepayAmount() public {
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: type(uint256).max,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Should create repay item
        assertEq(items.length, 1, "Should have 1 item for repay with max amount");
    }

    function test_SameOwnerAndAccount() public {
        mockBorrowVault.setDebt(OWNER, 1000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: OWNER, // Same as owner
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[0].onBehalfOfAccount, OWNER, "Should operate on behalf of same account");
    }

    function test_ZeroDebt() public {
        mockBorrowVault.setDebt(ACCOUNT, 0);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: 1000e18,
            kind: hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc" // KIND_BUY
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);
        assertEq(items.length, 1, "Should have 1 item");
    }
}
