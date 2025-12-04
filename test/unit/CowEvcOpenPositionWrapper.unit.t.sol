// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcOpenPositionWrapper} from "../../src/CowEvcOpenPositionWrapper.sol";
import {CowEvcBaseWrapper} from "../../src/CowEvcBaseWrapper.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";
import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";

// this is required because foundry doesn't have a cheatcode for override any transient storage.
contract TestableOpenPositionWrapper is CowEvcOpenPositionWrapper {
    constructor(address _evc, ICowSettlement _settlement) CowEvcOpenPositionWrapper(_evc, _settlement) {}

    function setExpectedEvcInternalSettleCall(bytes memory call) external {
        expectedEvcInternalSettleCallHash = keccak256(call);
    }
}

/// @title Unit tests for CowEvcOpenPositionWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcOpenPositionWrapperUnitTest is Test {
    TestableOpenPositionWrapper public wrapper;
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address constant SOLVER = address(0x3333);
    address constant COLLATERAL_VAULT = address(0x4444);
    address constant BORROW_VAULT = address(0x5555);

    uint256 constant DEFAULT_COLLATERAL_AMOUNT = 1000e18;
    uint256 constant DEFAULT_BORROW_AMOUNT = 500e18;

    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    /// @notice Get default OpenPositionParams for testing
    function _getDefaultParams() internal view returns (CowEvcOpenPositionWrapper.OpenPositionParams memory) {
        return CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: DEFAULT_COLLATERAL_AMOUNT,
            borrowAmount: DEFAULT_BORROW_AMOUNT
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

    /// @notice Encode wrapper data with length prefix
    function _encodeWrapperData(CowEvcOpenPositionWrapper.OpenPositionParams memory params, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory wrapperData = abi.encode(params, signature);
        return abi.encodePacked(uint16(wrapperData.length), wrapperData);
    }

    /// @notice Setup pre-approved hash flow
    function _setupPreApprovedHash(CowEvcOpenPositionWrapper.OpenPositionParams memory params)
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

        wrapper = new TestableOpenPositionWrapper(address(mockEvc), ICowSettlement(address(mockSettlement)));

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
                keccak256("CowEvcOpenPositionWrapper"),
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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithExtraData() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params1 = _getDefaultParams();

        // Change owner field
        CowEvcOpenPositionWrapper.OpenPositionParams memory params2 = _getDefaultParams();
        params2.owner = ACCOUNT;

        // Change borrowAmount field
        CowEvcOpenPositionWrapper.OpenPositionParams memory params3 = _getDefaultParams();
        params3.borrowAmount = 600e18;

        bytes32 hash1 = wrapper.getApprovalHash(params1);
        bytes32 hash2 = wrapper.getApprovalHash(params2);
        bytes32 hash3 = wrapper.getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    function test_GetApprovalHash_MatchesEIP712() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes32 structHash = keccak256(
            abi.encode(
                params.owner,
                params.account,
                params.deadline,
                params.collateralVault,
                params.borrowVault,
                params.collateralAmount,
                params.borrowAmount
            )
        );

        bytes32 expectedDigest = keccak256(abi.encodePacked("\x19\x01", wrapper.DOMAIN_SEPARATOR(), structHash));
        bytes32 actualDigest = wrapper.getApprovalHash(params);

        assertEq(actualDigest, expectedDigest, "Hash should match EIP-712 format");
    }

    /*//////////////////////////////////////////////////////////////
                    GET SIGNED CALLDATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetSignedCalldata_EnableCollateralItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[0].targetContract, address(mockEvc), "First item should target EVC");
        assertEq(
            items[0].data,
            abi.encodeCall(IEVC.enableCollateral, (ACCOUNT, COLLATERAL_VAULT)),
            "Should enable collateral"
        );
    }

    function test_GetSignedCalldata_EnableControllerItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[1].targetContract, address(mockEvc), "Second item should target EVC");
        assertEq(
            items[1].data, abi.encodeCall(IEVC.enableController, (ACCOUNT, BORROW_VAULT)), "Should enable controller"
        );
    }

    function test_GetSignedCalldata_DepositItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[2].targetContract, COLLATERAL_VAULT, "Third item should target collateral vault");
        assertEq(items[2].onBehalfOfAccount, OWNER, "Should deposit on behalf of owner");
        assertEq(
            items[2].data,
            abi.encodeCall(IERC4626.deposit, (DEFAULT_COLLATERAL_AMOUNT, ACCOUNT)),
            "Should deposit collateral"
        );
    }

    function test_GetSignedCalldata_BorrowItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[3].targetContract, BORROW_VAULT, "Fourth item should target borrow vault");
        assertEq(items[3].onBehalfOfAccount, ACCOUNT, "Should borrow on behalf of account");
        assertEq(
            items[3].data, abi.encodeCall(IBorrowing.borrow, (DEFAULT_BORROW_AMOUNT, OWNER)), "Should borrow to owner"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    EVC INTERNAL SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EvcInternalSettle_OnlyEVC() public {
        bytes memory settleData = "";
        bytes memory remainingWrapperData = "";

        vm.expectRevert(abi.encodeWithSelector(CowEvcBaseWrapper.Unauthorized.selector, address(this)));
        wrapper.evcInternalSettle(settleData, hex"", remainingWrapperData);
    }

    function test_EvcInternalSettle_RequiresCorrectCalldata() public {
        bytes memory settleData = _getEmptySettleData();
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        // Set incorrect onBehalfOfAccount (not address(wrapper))
        mockEvc.setOnBehalfOf(address(0x9999));

        // set incorrect expected call
        wrapper.setExpectedEvcInternalSettleCall(
            abi.encodeCall(wrapper.evcInternalSettle, (new bytes(0), new bytes(0), remainingWrapperData))
        );

        vm.prank(address(mockEvc));
        vm.expectRevert(CowEvcBaseWrapper.InvalidCallback.selector);
        wrapper.evcInternalSettle(settleData, hex"", remainingWrapperData);
    }

    function test_EvcInternalSettle_CanBeCalledByEVC() public {
        bytes memory settleData = _getEmptySettleData();
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        wrapper.setExpectedEvcInternalSettleCall(
            abi.encodeCall(wrapper.evcInternalSettle, (settleData, hex"", remainingWrapperData))
        );

        vm.prank(address(mockEvc));
        wrapper.evcInternalSettle(settleData, hex"", remainingWrapperData);
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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes memory signature = new bytes(65); // Valid ECDSA signature length
        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, signature);

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes32 hash = _setupPreApprovedHash(params);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        // Verify hash was consumed
        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_PreApprovedHashRevertsIfDeadlineExceeded() public {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();
        params.deadline = block.timestamp - 1; // Deadline in the past

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

    function test_ZeroCollateralAmount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();
        params.collateralAmount = 0; // Zero collateral

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Should still have deposit call, just with 0 amount
        assertEq(items[2].data, abi.encodeCall(IERC4626.deposit, (0, ACCOUNT)), "Should deposit 0");
    }

    function test_MaxBorrowAmount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();
        params.borrowAmount = type(uint256).max;

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[3].data, abi.encodeCall(IBorrowing.borrow, (type(uint256).max, OWNER)), "Should borrow max");
    }

    function test_SameOwnerAndAccount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();
        params.account = OWNER; // Same as owner

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Should still work, but with same address
        assertEq(items[2].onBehalfOfAccount, OWNER, "Deposit should be on behalf of owner");
        assertEq(items[3].onBehalfOfAccount, OWNER, "Borrow should be on behalf of account");
    }
}
