// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import "forge-std/Test.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcOpenPositionWrapper} from "../../src/CowEvcOpenPositionWrapper.sol";
import {CowSettlement, CowAuthentication} from "../../src/vendor/CowWrapper.sol";
import {IERC4626, IBorrowing, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";

/// @title Unit tests for CowEvcOpenPositionWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcOpenPositionWrapperUnitTest is Test {
    CowEvcOpenPositionWrapper public wrapper;
    MockEVC public mockEVC;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address constant SOLVER = address(0x3333);
    address constant COLLATERAL_VAULT = address(0x4444);
    address constant BORROW_VAULT = address(0x5555);

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

        wrapper = new CowEvcOpenPositionWrapper(address(mockEVC), CowSettlement(address(mockSettlement)));

        // Set solver as authenticated
        mockAuth.setSolver(SOLVER, true);
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
                keccak256("CowEvcOpenPositionWrapper"),
                keccak256("1"),
                block.chainid,
                address(wrapper)
            )
        );
        assertEq(wrapper.DOMAIN_SEPARATOR(), expectedDomainSeparator, "DOMAIN_SEPARATOR incorrect");
    }

    function test_Constructor_SetsName() public view {
        assertEq(wrapper.name(), "Euler EVC - Open Position", "Name not set correctly");
    }

    /*//////////////////////////////////////////////////////////////
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ParseWrapperData_EmptySignature() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithSignature() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signature = new bytes(65);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithExtraData() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes32 hash1 = wrapper.getApprovalHash(params);
        bytes32 hash2 = wrapper.getApprovalHash(params);

        assertEq(hash1, hash2, "Hash should be consistent");
    }

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params1 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        // same as params1 except owner field
        CowEvcOpenPositionWrapper.OpenPositionParams memory params2 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: ACCOUNT,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        // same as params1 except borrowAmount (the last) field
        CowEvcOpenPositionWrapper.OpenPositionParams memory params3 = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 600e18
        });

        bytes32 hash1 = wrapper.getApprovalHash(params1);
        bytes32 hash2 = wrapper.getApprovalHash(params2);
        bytes32 hash3 = wrapper.getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    function test_GetApprovalHash_MatchesEIP712() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

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

    function test_GetSignedCalldata_ReturnsCorrectStructure() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items.length, 4, "Should have 4 batch items");
    }

    function test_GetSignedCalldata_EnableCollateralItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[0].targetContract, address(mockEVC), "First item should target EVC");
        assertEq(
            items[0].data,
            abi.encodeCall(IEVC.enableCollateral, (ACCOUNT, COLLATERAL_VAULT)),
            "Should enable collateral"
        );
    }

    function test_GetSignedCalldata_EnableControllerItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[1].targetContract, address(mockEVC), "Second item should target EVC");
        assertEq(
            items[1].data, abi.encodeCall(IEVC.enableController, (ACCOUNT, BORROW_VAULT)), "Should enable controller"
        );
    }

    function test_GetSignedCalldata_DepositItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[2].targetContract, COLLATERAL_VAULT, "Third item should target collateral vault");
        assertEq(items[2].onBehalfOfAccount, OWNER, "Should deposit on behalf of owner");
        assertEq(items[2].data, abi.encodeCall(IERC4626.deposit, (1000e18, ACCOUNT)), "Should deposit collateral");
    }

    function test_GetSignedCalldata_BorrowItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[3].targetContract, BORROW_VAULT, "Fourth item should target borrow vault");
        assertEq(items[3].onBehalfOfAccount, ACCOUNT, "Should borrow on behalf of account");
        assertEq(items[3].data, abi.encodeCall(IBorrowing.borrow, (500e18, OWNER)), "Should borrow to owner");
    }

    /*//////////////////////////////////////////////////////////////
                    EVC INTERNAL SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EvcInternalSettle_OnlyEVC() public {
        bytes memory settleData = "";
        bytes memory remainingWrapperData = "";

        vm.expectRevert(abi.encodeWithSelector(CowEvcOpenPositionWrapper.Unauthorized.selector, address(this)));
        wrapper.evcInternalSettle(settleData, remainingWrapperData);
    }

    function test_EvcInternalSettle_CanBeCalledByEVC() public {
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
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSettle(settleData, remainingWrapperData);
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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signature = new bytes(65); // Valid ECDSA signature length
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
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        // Make user an operator
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

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        // Verify hash was consumed
        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_PreApprovedHashRevertsIfDeadlineExceeded() public {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp - 1, // Deadline in the past
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
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
                CowEvcOpenPositionWrapper.OperationDeadlineExceeded.selector, params.deadline, block.timestamp
            )
        );
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ZeroCollateralAmount() public {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 0, // Zero collateral
            borrowAmount: 500e18
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Should still have deposit call, just with 0 amount
        assertEq(items[2].data, abi.encodeCall(IERC4626.deposit, (0, ACCOUNT)), "Should deposit 0");
    }

    function test_MaxBorrowAmount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: type(uint256).max
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[3].data, abi.encodeCall(IBorrowing.borrow, (type(uint256).max, OWNER)), "Should borrow max");
    }

    function test_SameOwnerAndAccount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: OWNER, // Same as owner
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Should still work, but with same address
        assertEq(items[2].onBehalfOfAccount, OWNER, "Deposit should be on behalf of owner");
        assertEq(items[3].onBehalfOfAccount, OWNER, "Borrow should be on behalf of account");
    }
}
