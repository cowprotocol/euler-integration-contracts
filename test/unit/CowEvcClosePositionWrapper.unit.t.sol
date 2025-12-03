// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcClosePositionWrapper} from "../../src/CowEvcClosePositionWrapper.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";
import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";
import {MockERC20, MockVault, MockBorrowVault} from "./mocks/MockERC20AndVaults.sol";

// this is required because foundry doesn't have a cheatcode for override any transient storage.
contract TestableClosePositionWrapper is CowEvcClosePositionWrapper {
    constructor(address _evc, ICowSettlement _settlement) CowEvcClosePositionWrapper(_evc, _settlement) {}

    function setExpectedEvcInternalSettleCall(bytes memory call) external {
        expectedEvcInternalSettleCallHash = keccak256(call);
    }
}

/// @title Unit tests for CowEvcClosePositionWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcClosePositionWrapperUnitTest is Test {
    TestableClosePositionWrapper public wrapper;
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;
    MockERC20 public mockAsset;
    MockVault public mockCollateralVault;
    MockBorrowVault public mockBorrowVault;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address constant SOLVER = address(0x3333);

    uint256 constant DEFAULT_REPAY_AMOUNT = 1000e18;
    bytes32 constant KIND_BUY = hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc";

    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    /// @notice Get default ClosePositionParams for testing
    function _getDefaultParams() internal view returns (CowEvcClosePositionWrapper.ClosePositionParams memory) {
        return CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0,
            repayAmount: DEFAULT_REPAY_AMOUNT,
            kind: KIND_BUY
        });
    }

    /// @notice Create empty settle data
    function _getEmptySettleData() internal pure returns (bytes memory) {
        return abi.encodeCall(
            ICowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new ICowSettlement.Trade[](0),
                [
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0)
                ]
            )
        );
    }

    /// @notice Create settle data with tokens and prices
    function _getSettleDataWithTokens() internal view returns (bytes memory) {
        address[] memory tokens = new address[](2);
        tokens[0] = mockBorrowVault.asset();
        tokens[1] = address(mockCollateralVault);
        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18;
        prices[1] = 1e18;

        return abi.encodeCall(
            ICowSettlement.settle,
            (
                tokens,
                prices,
                new ICowSettlement.Trade[](0),
                [
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0)
                ]
            )
        );
    }

    /// @notice Encode wrapper data with length prefix
    function _encodeWrapperData(CowEvcClosePositionWrapper.ClosePositionParams memory params, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory wrapperData = abi.encode(params, signature);
        return abi.encodePacked(uint16(wrapperData.length), wrapperData);
    }

    /// @notice Setup pre-approved hash flow
    function _setupPreApprovedHash(CowEvcClosePositionWrapper.ClosePositionParams memory params)
        internal
        returns (bytes32)
    {
        bytes32 hash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);
        mockEvc.setOperator(OWNER, address(wrapper), true);
        mockEvc.setOperator(ACCOUNT, address(wrapper), true);
        return hash;
    }

    /// @notice Decode signed calldata helper
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
        mockEvc = new MockEVC();
        mockAsset = new MockERC20("Mock Asset", "MOCK");
        mockCollateralVault = new MockVault(address(mockAsset), "Mock Collateral", "mCOL");
        mockBorrowVault = new MockBorrowVault(address(mockAsset), "Mock Borrow", "mBOR");

        wrapper = new TestableClosePositionWrapper(address(mockEvc), ICowSettlement(address(mockSettlement)));

        // Set solver as authenticated
        mockAuth.setSolver(SOLVER, true);

        // Set the correct onBehalfOfAccount for evcInternalSettle calls
        mockEvc.setOnBehalfOf(address(wrapper));
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(wrapper.EVC()), address(mockEvc), "EVC not set correctly");
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

    /*//////////////////////////////////////////////////////////////
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ParseWrapperData_EmptySignature() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithExtraData() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

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

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params1 = _getDefaultParams();

        // Change owner field
        CowEvcClosePositionWrapper.ClosePositionParams memory params2 = _getDefaultParams();
        params2.owner = ACCOUNT;

        // Change repayAmount field
        CowEvcClosePositionWrapper.ClosePositionParams memory params3 = _getDefaultParams();
        params3.repayAmount = 2000e18;

        bytes32 hash1 = wrapper.getApprovalHash(params1);
        bytes32 hash2 = wrapper.getApprovalHash(params2);
        bytes32 hash3 = wrapper.getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    function test_GetApprovalHash_MatchesEIP712() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

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

    function test_GetSignedCalldata_PartialRepay() public {
        mockBorrowVault.setDebt(ACCOUNT, DEFAULT_REPAY_AMOUNT);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.repayAmount = 500e18; // Less than debt

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items.length, 1, "Should have 1 batch item for partial repay");
    }

    function test_GetSignedCalldata_RepayItem() public {
        mockBorrowVault.setDebt(ACCOUNT, DEFAULT_REPAY_AMOUNT);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

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

    /*//////////////////////////////////////////////////////////////
                    HELPER REPAY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_HelperRepay_SuccessfulRepay() public {
        // Give owner some tokens (not wrapper)
        mockAsset.mint(OWNER, 1000e18);

        // Owner must approve wrapper to spend their tokens
        vm.prank(OWNER);
        mockAsset.approve(address(wrapper), 1000e18);

        // Set up borrow vault with debt
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockBorrowVault.setRepayAmount(1000e18);

        // Set the correct onBehalfOfAccount for authentication check
        mockEvc.setOnBehalfOf(ACCOUNT);

        // Call through EVC batch
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT))
        });

        vm.prank(address(mockEvc));
        mockEvc.batch(items);

        // Verify owner's tokens were used for repayment
        assertEq(mockAsset.balanceOf(OWNER), 0, "Owner should have no tokens left");
    }

    function test_HelperRepay_WithDust() public {
        // Give owner more tokens than needed for repay
        mockAsset.mint(OWNER, 1100e18);

        // Owner must approve wrapper to spend their tokens
        vm.prank(OWNER);
        mockAsset.approve(address(wrapper), 1100e18);

        // Set up borrow vault with debt
        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockBorrowVault.setRepayAmount(1000e18); // Only 1000 actually needed

        // Set the correct onBehalfOfAccount for authentication check
        mockEvc.setOnBehalfOf(ACCOUNT);

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT))
        });

        vm.prank(address(mockEvc));
        mockEvc.batch(items);

        // Owner should have 100 tokens left (1100 - 1000 repaid)
        assertEq(mockAsset.balanceOf(OWNER), 100e18, "Owner should have dust remaining");
    }

    function test_HelperRepay_PartialRepayWhenInsufficientBalance() public {
        // Give owner insufficient tokens to fully repay debt
        mockAsset.mint(OWNER, 500e18);

        // Owner must approve wrapper to spend their tokens
        vm.prank(OWNER);
        mockAsset.approve(address(wrapper), 500e18);

        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockBorrowVault.setRepayAmount(500e18); // Will only repay what's available

        // Set the correct onBehalfOfAccount for authentication check
        mockEvc.setOnBehalfOf(ACCOUNT);

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT))
        });

        vm.prank(address(mockEvc));
        mockEvc.batch(items);

        // Should repay partial amount (500e18)
        assertEq(mockAsset.balanceOf(OWNER), 0, "Owner should have no tokens left");
    }

    function test_HelperRepay_RepayAll() public {
        mockAsset.mint(OWNER, 1100e18);

        // Owner must approve wrapper to spend their tokens
        vm.prank(OWNER);
        mockAsset.approve(address(wrapper), 1100e18);

        mockBorrowVault.setDebt(ACCOUNT, 1000e18);
        mockBorrowVault.setRepayAmount(1000e18);

        // Set the correct onBehalfOfAccount for authentication check
        mockEvc.setOnBehalfOf(ACCOUNT);

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: ACCOUNT,
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(wrapper.helperRepay, (address(mockBorrowVault), OWNER, ACCOUNT))
        });

        vm.prank(address(mockEvc));
        mockEvc.batch(items);

        // Dust should remain with owner (100e18)
        assertEq(mockAsset.balanceOf(OWNER), 100e18, "Owner should have dust remaining");
    }

    function test_HelperRepay_OnlyEVC() public {
        vm.expectRevert(abi.encodeWithSelector(CowEvcClosePositionWrapper.Unauthorized.selector, address(this)));
        wrapper.helperRepay(address(mockBorrowVault), OWNER, ACCOUNT);
    }

    function test_HelperRepay_RequiresCorrectOnBehalfOfAccount() public {
        mockAsset.mint(OWNER, 1000e18);

        vm.prank(OWNER);
        mockAsset.approve(address(wrapper), 1000e18);

        mockBorrowVault.setDebt(ACCOUNT, 1000e18);

        // Create a batch item that specifies ACCOUNT but the helperRepay expects a different account
        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](1);
        address wrongAccount = address(0x9999);
        items[0] = IEVC.BatchItem({
            onBehalfOfAccount: wrongAccount, // This will be set as getCurrentOnBehalfOfAccount
            targetContract: address(wrapper),
            value: 0,
            data: abi.encodeCall(
                wrapper.helperRepay,
                (address(mockBorrowVault), OWNER, ACCOUNT) // But we're trying to repay for ACCOUNT
            )
        });

        vm.prank(address(mockEvc));
        vm.expectRevert(abi.encodeWithSelector(CowEvcClosePositionWrapper.Unauthorized.selector, wrongAccount));
        mockEvc.batch(items);
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

    function test_EvcInternalSettle_RequiresCorrectCalldata() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.account = OWNER;

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        // Set incorrect onBehalfOfAccount (not address(wrapper))
        mockEvc.setOnBehalfOf(address(0x9999));

        // the wrapper data is omitted in the expected call
        wrapper.setExpectedEvcInternalSettleCall(
            abi.encodeCall(wrapper.evcInternalSettle, (settleData, new bytes(0), remainingWrapperData))
        );

        vm.prank(address(mockEvc));
        vm.expectRevert(CowEvcClosePositionWrapper.InvalidCallback.selector);
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSettle_CanBeCalledByEVC() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.account = OWNER; // Same account, no transfer needed

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        wrapper.setExpectedEvcInternalSettleCall(
            abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
        );

        vm.prank(address(mockEvc));
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

        vm.prank(OWNER);
        mockCollateralVault.approve(address(wrapper), 2000e18);

        // Create settle data with tokens and prices
        address[] memory tokens = new address[](2);
        tokens[0] = address(mockCollateralVault);
        tokens[1] = address(mockAsset);

        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18; // 1:1 price for simplicity
        prices[1] = 1e18;

        bytes memory settleData = abi.encodeCall(
            ICowSettlement.settle,
            (
                tokens,
                prices,
                new ICowSettlement.Trade[](0),
                [
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        wrapper.setExpectedEvcInternalSettleCall(
            abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
        );

        vm.prank(address(mockEvc));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);

        // Verify owner has same balance before (because the balance is kept the same by the wrapper)
        assertEq(
            mockCollateralVault.balanceOf(OWNER),
            0,
            "Owner should not have a balance change after the operation is complete"
        );
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
            ICowSettlement.settle,
            (
                tokens,
                prices,
                new ICowSettlement.Trade[](0),
                [
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        wrapper.setExpectedEvcInternalSettleCall(
            abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
        );

        vm.prank(address(mockEvc));
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

        // Mint repayment assets to OWNER (not wrapper) since helperRepay pulls from owner
        MockERC20(mockBorrowVault.asset()).mint(OWNER, 1000e18);

        // Owner must approve wrapper to spend repayment assets
        vm.prank(OWNER);
        MockERC20(mockBorrowVault.asset()).approve(address(wrapper), 1000e18);

        // These tokens need to be spendable by the wrapper
        vm.prank(ACCOUNT);
        mockCollateralVault.approve(address(wrapper), 2000e18);

        vm.prank(OWNER);
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
            ICowSettlement.settle,
            (
                tokens,
                prices,
                new ICowSettlement.Trade[](0),
                [
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        mockBorrowVault.setDebt(ACCOUNT, DEFAULT_REPAY_AMOUNT);
        mockCollateralVault.mint(ACCOUNT, 2000e18);
        MockERC20(mockBorrowVault.asset()).mint(OWNER, DEFAULT_REPAY_AMOUNT);

        vm.startPrank(OWNER);
        MockERC20(mockBorrowVault.asset()).approve(address(wrapper), DEFAULT_REPAY_AMOUNT);
        vm.stopPrank();

        vm.prank(ACCOUNT);
        mockCollateralVault.approve(address(wrapper), 2000e18);

        vm.prank(OWNER);
        mockCollateralVault.approve(address(wrapper), 2000e18);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes32 hash = _setupPreApprovedHash(params);

        bytes memory settleData = _getSettleDataWithTokens();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_PreApprovedHashRevertsIfDeadlineExceeded() public {
        mockBorrowVault.setDebt(ACCOUNT, DEFAULT_REPAY_AMOUNT);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.deadline = block.timestamp - 1; // Past deadline

        _setupPreApprovedHash(params);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

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
        mockBorrowVault.setDebt(ACCOUNT, DEFAULT_REPAY_AMOUNT);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.repayAmount = type(uint256).max;

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Should create repay item
        assertEq(items.length, 1, "Should have 1 item for repay with max amount");
    }

    function test_SameOwnerAndAccount() public {
        mockBorrowVault.setDebt(OWNER, DEFAULT_REPAY_AMOUNT);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.account = OWNER; // Same as owner

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[0].onBehalfOfAccount, OWNER, "Should operate on behalf of same account");
    }

    function test_ZeroDebt() public {
        mockBorrowVault.setDebt(ACCOUNT, 0);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);
        assertEq(items.length, 1, "Should have 1 item");
    }
}
