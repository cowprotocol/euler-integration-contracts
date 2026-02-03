// SPDX-License-Identifier: GPL-2.0-or-later
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
}
