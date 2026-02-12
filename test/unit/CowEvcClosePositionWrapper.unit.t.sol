// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcClosePositionWrapper} from "../../src/CowEvcClosePositionWrapper.sol";
import {CowEvcBaseWrapper} from "../../src/CowEvcBaseWrapper.sol";
import {PreApprovedHashes} from "../../src/PreApprovedHashes.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";
import {MockERC20, MockVault, MockBorrowVault} from "./mocks/MockERC20AndVaults.sol";
import {UnitTestBase} from "./UnitTestBase.sol";
import {IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

// this is required because foundry doesn't have a cheatcode for override any transient storage.
contract TestableClosePositionWrapper is CowEvcClosePositionWrapper {
    constructor(address _evc, ICowSettlement _settlement) CowEvcClosePositionWrapper(_evc, _settlement) {}

    function setExpectedEvcInternalSettleCall(bytes memory call) external {
        expectedEvcInternalSettleCallHash = keccak256(call);
    }
}

/// @title Unit tests for CowEvcClosePositionWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcClosePositionWrapperUnitTest is UnitTestBase {
    MockERC20 public mockCollateralAsset;
    MockVault public mockCollateralVault;
    MockERC20 public mockDebtAsset;
    MockBorrowVault public mockBorrowVault;

    uint256 constant DEFAULT_REPAY_AMOUNT = 1000e18;
    bytes32 constant KIND_BUY = keccak256("buy");

    /// @notice Get default ClosePositionParams for testing
    function _getDefaultParams() internal view returns (CowEvcClosePositionWrapper.ClosePositionParams memory) {
        return CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0
        });
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
        bytes32 hash = CowEvcClosePositionWrapper(address(wrapper)).getApprovalHash(params);
        vm.prank(params.owner);
        wrapper.setPreApprovedHash(hash, true);
        return hash;
    }

    function setUp() public override {
        super.setUp();

        mockCollateralAsset = new MockERC20("Mock Asset Collateral", "MOCKCOLL");
        mockDebtAsset = new MockERC20("Mock Asset Debt", "MOCKDEBT");
        mockCollateralVault = new MockVault(address(mockCollateralAsset), "Mock Collateral", "mCOL");
        mockBorrowVault = new MockBorrowVault(address(mockDebtAsset), "Mock Borrow", "mBOR");

        wrapper = CowEvcBaseWrapper(
            new TestableClosePositionWrapper(address(mockEvc), ICowSettlement(address(mockSettlement)))
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

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

    function test_ValidateWrapperData_EmptySignature() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes memory wrapperData = abi.encode(params, new bytes(0));

        // Should not revert for valid wrapper data
        wrapper.validateWrapperData(wrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    APPROVAL HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcClosePositionWrapper.ClosePositionParams memory params1 = _getDefaultParams();

        // Change owner field
        CowEvcClosePositionWrapper.ClosePositionParams memory params2 = _getDefaultParams();
        params2.owner = ACCOUNT;

        // Change collateralAmount field
        CowEvcClosePositionWrapper.ClosePositionParams memory params3 = _getDefaultParams();
        params3.collateralAmount = 1e18;

        bytes32 hash1 = CowEvcClosePositionWrapper(address(wrapper)).getApprovalHash(params1);
        bytes32 hash2 = CowEvcClosePositionWrapper(address(wrapper)).getApprovalHash(params2);
        bytes32 hash3 = CowEvcClosePositionWrapper(address(wrapper)).getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    /*//////////////////////////////////////////////////////////////
                    ENCODE PERMIT DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EncodePermitData_EncodesAsExpected() public {
        mockBorrowVault.setDebt(ACCOUNT, DEFAULT_REPAY_AMOUNT);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes memory permitData = CowEvcClosePositionWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items, bytes32 paramsHash) = _decodePermitData(permitData);

        assertEq(
            paramsHash, CowEvcClosePositionWrapper(address(wrapper)).getApprovalHash(params), "Params hash should match"
        );

        assertEq(items[0].targetContract, params.collateralVault, "First item should target EVC");
        assertEq(
            items[0].data,
            abi.encodeCall(
                IERC20.transfer,
                (
                    CowEvcClosePositionWrapper(address(wrapper)).getInbox(params.owner, params.account),
                    params.collateralAmount
                )
            ),
            "Should enable collateral"
        );

        assertEq(items.length, 1, "Should have 1 batch item for partial repay");
    }

    /*//////////////////////////////////////////////////////////////
                    EVC INTERNAL SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EvcInternalSettle_RequiresFundsInInbox() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.account = OWNER; // Same account, no transfer needed

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        TestableClosePositionWrapper(address(wrapper))
            .setExpectedEvcInternalSettleCall(
                abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
            );

        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcClosePositionWrapper.NoSwapOutput.selector,
                CowEvcClosePositionWrapper(address(wrapper)).getInbox(params.owner, params.account)
            )
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
            collateralAmount: 1000e18
        });

        address inbox = CowEvcClosePositionWrapper(address(wrapper)).getInbox(params.owner, params.account);

        // Give  some collateral vault tokens (what it would received previously from transferring from the user in the EVC.permit)
        mockCollateralVault.mint(inbox, 5000e18);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        TestableClosePositionWrapper(address(wrapper))
            .setExpectedEvcInternalSettleCall(
                abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
            );

        // put funds in the inbox so it doesn't revert
        deal(address(mockDebtAsset), inbox, 1);

        vm.prank(address(mockEvc));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);

        // Verify inbox has no funds and subaccount has same balance as before (because any unused funds are returned)
        assertEq(
            mockCollateralVault.balanceOf(inbox),
            0,
            "Inbox should not have any funds left over because it all gets sent back to the subaccount"
        );
        assertEq(mockCollateralVault.balanceOf(ACCOUNT), 5000e18, "Account should have everything returned to it");
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
        CowEvcClosePositionWrapper.ClosePositionParams memory params = CowEvcClosePositionWrapper.ClosePositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            borrowVault: address(mockBorrowVault),
            collateralVault: address(mockCollateralVault),
            collateralAmount: 0
        });

        bytes memory signature = new bytes(65);
        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        // put funds in the inbox so it doesn't revert
        deal(
            address(mockDebtAsset),
            CowEvcClosePositionWrapper(address(wrapper)).getInbox(params.owner, params.account),
            1
        );

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes32 hash = _setupPreApprovedHash(params);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        // put funds in the inbox so it doesn't revert
        deal(
            address(mockDebtAsset),
            CowEvcClosePositionWrapper(address(wrapper)).getInbox(params.owner, params.account),
            1
        );

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_RevertsIfHashNotPreApproved() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        // Calculate hash but DO NOT pre-approve it
        bytes32 hash = CowEvcClosePositionWrapper(address(wrapper)).getApprovalHash(params);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0)); // Empty signature triggers pre-approved hash flow

        // Expect revert with HashNotApproved error
        vm.prank(SOLVER);
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.HashNotApproved.selector, OWNER, hash));
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_RevertsOnTamperedSignature() public {
        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData =
            _encodeWrapperData(params, hex"0000000000000000000000000000000000000000000000000000000000000000");

        vm.mockCallRevert(address(mockEvc), 0, abi.encodeWithSelector(IEVC.permit.selector), "permit failure");

        // Expect revert with ECDSA error when permit fails
        vm.prank(SOLVER);
        vm.expectRevert("permit failure");
        wrapper.wrappedSettle(settleData, wrapperData);
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
                CowEvcBaseWrapper.OperationDeadlineExceeded.selector, params.deadline, block.timestamp
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

        bytes memory permitData = CowEvcClosePositionWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items,) = _decodePermitData(permitData);

        // Should create repay item
        assertEq(items.length, 1, "Should have 1 item for repay with max amount");
    }

    function test_SameOwnerAndAccount() public {
        mockBorrowVault.setDebt(OWNER, DEFAULT_REPAY_AMOUNT);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();
        params.account = OWNER; // Same as owner

        bytes memory permitData = CowEvcClosePositionWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items,) = _decodePermitData(permitData);

        assertEq(items[0].onBehalfOfAccount, OWNER, "Should operate on behalf of same account");
    }

    function test_ZeroDebt() public {
        mockBorrowVault.setDebt(ACCOUNT, 0);

        CowEvcClosePositionWrapper.ClosePositionParams memory params = _getDefaultParams();

        bytes memory permitData = CowEvcClosePositionWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items,) = _decodePermitData(permitData);
        assertEq(items.length, 1, "Should have 1 item");
    }
}
