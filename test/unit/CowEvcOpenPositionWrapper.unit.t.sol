// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcOpenPositionWrapper} from "../../src/CowEvcOpenPositionWrapper.sol";
import {CowSettlement} from "../../src/vendor/CowWrapper.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";
import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";

/// @title Unit tests for CowEvcOpenPositionWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcOpenPositionWrapperUnitTest is Test {
    CowEvcOpenPositionWrapper public wrapper;
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address constant SOLVER = address(0x3333);
    address constant COLLATERAL_VAULT = address(0x4444);
    address constant BORROW_VAULT = address(0x5555);

    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    function setUp() public {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEvc = new MockEVC();

        wrapper = new CowEvcOpenPositionWrapper(address(mockEvc), CowSettlement(address(mockSettlement)));

        mockAuth.setSolver(SOLVER, true);
        mockEvc.setOnBehalfOf(address(wrapper));
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _defaultParams() internal view returns (CowEvcOpenPositionWrapper.OpenPositionParams memory) {
        return CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: 1000e18,
            borrowAmount: 500e18
        });
    }

    function _emptySettleData() internal pure returns (bytes memory) {
        return abi.encodeCall(
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
    }

    function _decodeSignedCalldata(bytes memory signedCalldata) internal pure returns (IEVC.BatchItem[] memory) {
        bytes memory encodedItems = new bytes(signedCalldata.length - 4);
        for (uint256 i = 4; i < signedCalldata.length; i++) {
            encodedItems[i - 4] = signedCalldata[i];
        }
        return abi.decode(encodedItems, (IEVC.BatchItem[]));
    }

    function _assertBatchItemStructure(
        IEVC.BatchItem memory item,
        address expectedTarget,
        address expectedOnBehalf,
        bytes memory expectedData,
        string memory errorMsg
    ) internal pure {
        assertEq(item.targetContract, expectedTarget, string.concat(errorMsg, ": target"));
        assertEq(item.onBehalfOfAccount, expectedOnBehalf, string.concat(errorMsg, ": onBehalf"));
        assertEq(item.data, expectedData, string.concat(errorMsg, ": data"));
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

    function test_Constructor_SetsName() public view {
        assertEq(wrapper.name(), "Euler EVC - Open Position", "Name not set correctly");
    }

    /*//////////////////////////////////////////////////////////////
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ParseWrapperData_EmptySignature() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithSignature() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory signature = new bytes(65);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithExtraData() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes32 hash1 = wrapper.getApprovalHash(params);
        bytes32 hash2 = wrapper.getApprovalHash(params);

        assertEq(hash1, hash2, "Hash should be consistent");
    }

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params1 = _defaultParams();

        CowEvcOpenPositionWrapper.OpenPositionParams memory params2 = _defaultParams();
        params2.owner = ACCOUNT; // Change owner

        CowEvcOpenPositionWrapper.OpenPositionParams memory params3 = _defaultParams();
        params3.borrowAmount = 600e18; // Change borrowAmount

        bytes32 hash1 = wrapper.getApprovalHash(params1);
        bytes32 hash2 = wrapper.getApprovalHash(params2);
        bytes32 hash3 = wrapper.getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    function test_GetApprovalHash_MatchesEIP712() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();

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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items.length, 4, "Should have 4 batch items");

        // Verify each batch item using vm.expectCall pattern
        assertEq(items[0].targetContract, address(mockEvc));
        assertEq(items[0].data, abi.encodeCall(IEVC.enableCollateral, (ACCOUNT, COLLATERAL_VAULT)));

        assertEq(items[1].targetContract, address(mockEvc));
        assertEq(items[1].data, abi.encodeCall(IEVC.enableController, (ACCOUNT, BORROW_VAULT)));

        assertEq(items[2].targetContract, COLLATERAL_VAULT);
        assertEq(items[2].onBehalfOfAccount, OWNER);
        assertEq(items[2].data, abi.encodeCall(IERC4626.deposit, (1000e18, ACCOUNT)));

        assertEq(items[3].targetContract, BORROW_VAULT);
        assertEq(items[3].onBehalfOfAccount, ACCOUNT);
        assertEq(items[3].data, abi.encodeCall(IBorrowing.borrow, (500e18, OWNER)));
    }

    function test_GetSignedCalldata_EnableCollateralItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        _assertBatchItemStructure(
            items[0],
            address(mockEvc),
            address(0),
            abi.encodeCall(IEVC.enableCollateral, (ACCOUNT, COLLATERAL_VAULT)),
            "EnableCollateral"
        );
    }

    function test_GetSignedCalldata_EnableControllerItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        _assertBatchItemStructure(
            items[1],
            address(mockEvc),
            address(0),
            abi.encodeCall(IEVC.enableController, (ACCOUNT, BORROW_VAULT)),
            "EnableController"
        );
    }

    function test_GetSignedCalldata_DepositItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        _assertBatchItemStructure(
            items[2],
            COLLATERAL_VAULT,
            OWNER,
            abi.encodeCall(IERC4626.deposit, (1000e18, ACCOUNT)),
            "Deposit"
        );
    }

    function test_GetSignedCalldata_BorrowItem() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        _assertBatchItemStructure(
            items[3], BORROW_VAULT, ACCOUNT, abi.encodeCall(IBorrowing.borrow, (500e18, OWNER)), "Borrow"
        );
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

    function test_EvcInternalSettle_RequiresCorrectOnBehalfOfAccount() public {
        bytes memory settleData = _emptySettleData();
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);
        mockEvc.setOnBehalfOf(address(0x9999));

        vm.prank(address(mockEvc));
        vm.expectRevert(abi.encodeWithSelector(CowEvcOpenPositionWrapper.Unauthorized.selector, address(0x9999)));
        wrapper.evcInternalSettle(settleData, remainingWrapperData);
    }

    function test_EvcInternalSettle_CanBeCalledByEVC() public {
        bytes memory settleData = _emptySettleData();
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEvc));
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
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes memory signature = new bytes(65);
        bytes memory settleData = _emptySettleData();
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        mockEvc.setOperator(OWNER, address(wrapper), true);
        mockEvc.setOperator(ACCOUNT, address(wrapper), true);

        bytes memory settleData = _emptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_PreApprovedHashRevertsIfDeadlineExceeded() public {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        params.deadline = block.timestamp - 1;

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        mockEvc.setOperator(OWNER, address(wrapper), true);
        mockEvc.setOperator(ACCOUNT, address(wrapper), true);

        bytes memory settleData = _emptySettleData();
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

    function test_ZeroCollateralAmount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        params.collateralAmount = 0;

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[2].data, abi.encodeCall(IERC4626.deposit, (0, ACCOUNT)), "Should deposit 0");
    }

    function test_MaxBorrowAmount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        params.borrowAmount = type(uint256).max;

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[3].data, abi.encodeCall(IBorrowing.borrow, (type(uint256).max, OWNER)), "Should borrow max");
    }

    function test_SameOwnerAndAccount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _defaultParams();
        params.account = OWNER;

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[2].onBehalfOfAccount, OWNER, "Deposit should be on behalf of owner");
        assertEq(items[3].onBehalfOfAccount, OWNER, "Borrow should be on behalf of account");
    }
}
