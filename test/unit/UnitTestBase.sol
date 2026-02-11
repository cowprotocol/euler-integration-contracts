// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";
import {ICowSettlement, CowWrapper} from "../../src/CowWrapper.sol";
import {PreApprovedHashes} from "../../src/PreApprovedHashes.sol";
import {CowEvcBaseWrapper} from "../../src/CowEvcBaseWrapper.sol";
import {EmptyWrapper} from "../EmptyWrapper.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";

abstract contract UnitTestBase is Test {
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;
    EmptyWrapper public emptyWrapper;

    CowEvcBaseWrapper public wrapper;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address immutable SOLVER = makeAddr("solver");
    address immutable COLLATERAL_VAULT = makeAddr("collateral vault");
    address immutable BORROW_VAULT = makeAddr("borrow vault");

    function setUp() public virtual {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEvc = new MockEVC();
        emptyWrapper = new EmptyWrapper(ICowSettlement(address(mockSettlement)));

        // Set solver as authenticated
        mockAuth.setSolver(SOLVER, true);

        vm.label(OWNER, "OWNER");
        vm.label(ACCOUNT, "ACCOUNT");
    }

    function _encodeDefaultWrapperData(bytes memory signature) internal view virtual returns (bytes memory wrapperData);

    function _setupPreApprovedHashDefaultParams() internal virtual returns (bytes32);

    /// @notice Helper to get the decoded IEVC.BatchItem[] from a call to `encodePermitData`
    function _decodePermitData(bytes memory permitData)
        internal
        pure
        returns (IEVC.BatchItem[] memory items, bytes32 paramsHash)
    {
        bytes memory encodedItems = new bytes(permitData.length - 4);
        for (uint256 i = 4; i < permitData.length; i++) {
            encodedItems[i - 4] = permitData[i];
        }

        items = abi.decode(encodedItems, (IEVC.BatchItem[]));

        // normally we subtract 64 here but the length field is at beginning so its just `length`
        uint256 pos = permitData.length;
        assembly {
            paramsHash := mload(add(permitData, pos))
        }
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

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(wrapper.EVC()), address(mockEvc), "EVC not set correctly");
        assertEq(address(wrapper.SETTLEMENT()), address(mockSettlement), "SETTLEMENT not set correctly");
        assertEq(address(wrapper.AUTHENTICATOR()), address(mockAuth), "AUTHENTICATOR not set correctly");
        assertEq(wrapper.NONCE_NAMESPACE(), uint256(uint160(address(wrapper))), "NONCE_NAMESPACE incorrect");
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WrappedSettle_OnlySolver() public {
        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, address(this)));
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPermitSignature() public {
        bytes memory signature = new bytes(65);
        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeDefaultWrapperData(signature);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        bytes32 hash = _setupPreApprovedHashDefaultParams();

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeDefaultWrapperData(new bytes(0));

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_RevertsIfHashNotPreApproved() public {
        // Set operator permissions (required for EVC batch operations)

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeDefaultWrapperData(new bytes(0)); // Empty signature triggers pre-approved hash flow

        // Expect revert with HashNotApproved error (its sufficient to just verify the selector)
        vm.prank(SOLVER);
        vm.expectPartialRevert(PreApprovedHashes.HashNotApproved.selector);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_RevertsOnTamperedSignature() public {
        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData =
            _encodeDefaultWrapperData(hex"0000000000000000000000000000000000000000000000000000000000000000");

        vm.mockCallRevert(address(mockEvc), 0, abi.encodeWithSelector(IEVC.permit.selector), "permit failure");

        // Expect revert with ECDSA error when permit fails
        vm.prank(SOLVER);
        vm.expectRevert("permit failure");
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that validateWrapperData reverts on badly formatted input
    function test_ValidateWrapperData_ValidateWrapperDataMalformed() external {
        bytes memory malformedData = hex"deadbeef";
        vm.expectRevert(new bytes(0));
        wrapper.validateWrapperData(malformedData);
    }
}
