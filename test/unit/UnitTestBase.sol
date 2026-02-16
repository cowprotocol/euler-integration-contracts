// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";
import {CowEvcBaseWrapper} from "../../src/CowEvcBaseWrapper.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";

abstract contract UnitTestBase is Test {
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;

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

        // Set solver as authenticated
        mockAuth.setSolver(SOLVER, true);
    }

    /// @notice Helper to get the decoded IEVC.BatchItem[] and params hash from a call to `encodePermitData`
    function _decodePermitData(bytes memory permitData)
        internal
        pure
        returns (IEVC.BatchItem[] memory items, bytes32 paramsHash)
    {
        // The permit data is expected to be encoded as follows:
        // | IEVC.batch selector | abi-encoded batch entries | parameter hash |
        // | 4 bytes             | variable length           | 32 bytes       |

        uint256 itemByteLength = permitData.length - 4 - 32;
        bytes memory encodedItems = new bytes(itemByteLength);
        for (uint256 i = 0; i < itemByteLength; i++) {
            encodedItems[i] = permitData[i + 4];
        }
        items = abi.decode(encodedItems, (IEVC.BatchItem[]));

        uint256 parametersByteStart = 4 + itemByteLength;
        bytes memory encodedParameters = new bytes(itemByteLength);
        for (uint256 i = 0; i < 32; i++) {
            encodedParameters[i] = permitData[i + parametersByteStart];
        }
        paramsHash = abi.decode(encodedParameters, (bytes32));
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
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that validateWrapperData reverts on badly formatted input
    function test_ValidateWrapperData_ValidateWrapperDataMalformed() external {
        bytes memory malformedData = hex"deadbeef";
        vm.expectRevert(new bytes(0));
        wrapper.validateWrapperData(malformedData);
    }
}
