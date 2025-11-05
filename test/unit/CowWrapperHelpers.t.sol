// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapperHelpers} from "../../src/CowWrapperHelpers.sol";
import {ICowAuthentication, ICowSettlement} from "../../src/CowWrapper.sol";
import {MockCowSettlement, MockCowAuthentication, MockWrapper} from "./mocks/MockCowProtocol.sol";

contract CowWrapperHelpersTest is Test {
    CowWrapperHelpers helpers;
    MockCowAuthentication wrapperAuth;
    MockCowAuthentication solverAuth;
    MockCowSettlement mockSettlement;

    MockWrapper wrapper1;
    MockWrapper wrapper2;
    MockWrapper wrapper3;

    function setUp() public {
        wrapperAuth = new MockCowAuthentication();
        solverAuth = new MockCowAuthentication();
        helpers = new CowWrapperHelpers(ICowAuthentication(address(wrapperAuth)), ICowAuthentication(address(solverAuth)));

        mockSettlement = new MockCowSettlement(address(wrapperAuth));

        // Create mock wrappers
        wrapper1 = new MockWrapper(ICowSettlement(address(mockSettlement)), 4);
        wrapper2 = new MockWrapper(ICowSettlement(address(mockSettlement)), 8);
        wrapper3 = new MockWrapper(ICowSettlement(address(mockSettlement)), 0);

        // Add wrappers as solvers
        wrapperAuth.setSolver(address(wrapper1), true);
        wrapperAuth.setSolver(address(wrapper2), true);
        wrapperAuth.setSolver(address(wrapper3), true);
    }

    function test_verifyAndBuildWrapperData_EmptyArrays() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](0);

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should be empty
        assertEq(result, hex"");
    }

    function test_verifyAndBuildWrapperData_SingleWrapper() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should contain: data[0] only (no settlement appended)
        bytes memory expected = abi.encodePacked(uint16(4), hex"deadbeef");
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_MultipleWrappers() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](3);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: address(wrapper2), data: hex"cafebabe12345678"});
        wrapperCalls[2] = CowWrapperHelpers.WrapperCall({target: address(wrapper3), data: hex""});

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should contain: data[0] + target[1] + data[1] + target[2] + data[2] (no settlement)
        bytes memory expected = abi.encodePacked(
            uint16(4),
            hex"deadbeef",
            address(wrapper2),
            uint16(8),
            hex"cafebabe12345678",
            address(wrapper3),
            uint16(0),
            hex""
        );
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_RevertsOnNotAWrapper() public {
        address notAWrapper = makeAddr("notAWrapper");

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: notAWrapper, data: hex""});

        vm.expectRevert(
            abi.encodeWithSelector(CowWrapperHelpers.NotAWrapper.selector, 0, notAWrapper, address(wrapperAuth))
        );
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnNotAWrapper_SecondWrapper() public {
        address notAWrapper = makeAddr("notAWrapper");

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: notAWrapper, data: hex""});

        vm.expectRevert(
            abi.encodeWithSelector(CowWrapperHelpers.NotAWrapper.selector, 1, notAWrapper, address(wrapperAuth))
        );
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataNotFullyConsumed() public {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1), // Consumes 4 bytes
            data: hex"deadbeefcafe" // 6 bytes, but wrapper only consumes 4
        });

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataNotFullyConsumed.selector, 0, hex"cafe"));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataMalformed() public {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});

        bytes memory errorData = hex"feab";
        vm.mockCallRevert(address(wrapper1), abi.encodeWithSelector(wrapper1.parseWrapperData.selector), errorData);

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataMalformed.selector, 0, errorData));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnSettlementContractShouldNotBeSolver() public {
        // Add settlement as a solver (which should not be allowed)
        solverAuth.setSolver(address(mockSettlement), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});

        vm.expectRevert(
            abi.encodeWithSelector(
                CowWrapperHelpers.SettlementContractShouldNotBeSolver.selector,
                address(mockSettlement),
                address(solverAuth)
            )
        );
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_EmptyWrapperData() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper3), // Consumes 0 bytes
            data: hex""
        });
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper3), // Consumes 0 bytes
            data: hex""
        });

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should contain: data[0] + target[1] + data[1]
        bytes memory expected = abi.encodePacked(uint16(0), hex"", address(wrapper3), uint16(0), hex"");
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_MixedWrapperDataSizes() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](3);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper3), // Consumes 0 bytes
            data: hex""
        });
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1), // Consumes 4 bytes
            data: hex"deadbeef"
        });
        wrapperCalls[2] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper2), // Consumes 8 bytes
            data: hex"cafebabe12345678"
        });

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        bytes memory expected = abi.encodePacked(
            uint16(0),
            hex"",
            address(wrapper1),
            uint16(4),
            hex"deadbeef",
            address(wrapper2),
            uint16(8),
            hex"cafebabe12345678"
        );
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_RevertsOnSettlementMismatch() public {
        MockCowSettlement differentSettlement = new MockCowSettlement(address(wrapperAuth));
        MockWrapper differentWrapper = new MockWrapper(ICowSettlement(address(differentSettlement)), 4);
        wrapperAuth.setSolver(address(differentWrapper), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: address(differentWrapper), data: hex"cafebabe"});

        vm.expectRevert(
            abi.encodeWithSelector(
                CowWrapperHelpers.SettlementMismatch.selector, 1, address(mockSettlement), address(differentSettlement)
            )
        );
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_immutableAuthenticators() public view {
        assertEq(address(helpers.WRAPPER_AUTHENTICATOR()), address(wrapperAuth));
        assertEq(address(helpers.SOLVER_AUTHENTICATOR()), address(solverAuth));
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataTooLong_FirstWrapper() public {
        // Create data that's exactly 65536 bytes (exceeds uint16 max of 65535)
        bytes memory tooLongData = new bytes(65536);

        // Create a wrapper that consumes all bytes passed to it
        MockWrapper largeWrapper = new MockWrapper(ICowSettlement(address(mockSettlement)), 65536);
        wrapperAuth.setSolver(address(largeWrapper), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(largeWrapper), data: tooLongData});

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataTooLong.selector, 0, 65536));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataTooLong_SecondWrapper() public {
        // Create data that's exactly 65536 bytes for the second wrapper
        bytes memory tooLongData = new bytes(65536);

        // Create a wrapper that consumes all bytes passed to it
        MockWrapper largeWrapper = new MockWrapper(ICowSettlement(address(mockSettlement)), 65536);
        wrapperAuth.setSolver(address(largeWrapper), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"deadbeef"});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: address(largeWrapper), data: tooLongData});

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataTooLong.selector, 1, 65536));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_SucceedsWithMaxLengthData() public {
        // Create data that's exactly 65535 bytes (max valid uint16)
        bytes memory maxLengthData = new bytes(65535);

        // Create a wrapper that consumes all bytes
        MockWrapper largeWrapper = new MockWrapper(ICowSettlement(address(mockSettlement)), 65535);
        wrapperAuth.setSolver(address(largeWrapper), true);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(largeWrapper), data: maxLengthData});

        // Should not revert - 65535 is the max valid length
        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Verify the length prefix is correct (first 2 bytes)
        bytes2 lengthPrefix;
        assembly {
            lengthPrefix := mload(add(result, 32))
        }
        assertEq(uint16(lengthPrefix), 65535);
    }
}
