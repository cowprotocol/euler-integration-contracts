// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapperHelpers} from "../src/vendor/CowWrapperHelpers.sol";
import {CowWrapper, CowAuthentication, ICowWrapper} from "../src/vendor/CowWrapper.sol";

contract MockAuthenticator {
    mapping(address => bool) public solvers;

    function addSolver(address solver) external {
        solvers[solver] = true;
    }

    function isSolver(address solver) external view returns (bool) {
        return solvers[solver];
    }
}

contract MockWrapper is CowWrapper {
    uint256 public consumeBytes;

    constructor(CowAuthentication authenticator_, uint256 consumeBytes_) CowWrapper(authenticator_) {
        consumeBytes = consumeBytes_;
    }

    function _wrap(bytes calldata, bytes calldata) internal override {
        // Not used in these tests
    }

    function parseWrapperData(bytes calldata wrapperData) external view override returns (bytes calldata remainingWrapperData) {
        return wrapperData[consumeBytes:];
    }
}

contract BrokenWrapper is CowWrapper {
    constructor(CowAuthentication authenticator_) CowWrapper(authenticator_) {}

    function _wrap(bytes calldata, bytes calldata) internal override {
        // Not used in these tests
    }

    function parseWrapperData(bytes calldata) external pure override returns (bytes calldata) {
        revert("Intentionally broken");
    }
}

contract CowWrapperHelpersTest is Test {
    CowWrapperHelpers helpers;
    MockAuthenticator wrapperAuth;
    MockAuthenticator solverAuth;
    address settlement;

    MockWrapper wrapper1;
    MockWrapper wrapper2;
    MockWrapper wrapper3;
    BrokenWrapper brokenWrapper;

    function setUp() public {
        wrapperAuth = new MockAuthenticator();
        solverAuth = new MockAuthenticator();
        helpers = new CowWrapperHelpers(CowAuthentication(address(wrapperAuth)), CowAuthentication(address(solverAuth)));

        settlement = makeAddr("settlement");

        // Create mock wrappers
        wrapper1 = new MockWrapper(CowAuthentication(address(wrapperAuth)), 4);
        wrapper2 = new MockWrapper(CowAuthentication(address(wrapperAuth)), 8);
        wrapper3 = new MockWrapper(CowAuthentication(address(wrapperAuth)), 0);
        brokenWrapper = new BrokenWrapper(CowAuthentication(address(wrapperAuth)));

        // Add wrappers as solvers
        wrapperAuth.addSolver(address(wrapper1));
        wrapperAuth.addSolver(address(wrapper2));
        wrapperAuth.addSolver(address(wrapper3));
        wrapperAuth.addSolver(address(brokenWrapper));
    }

    function test_verifyAndBuildWrapperData_EmptyArrays() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](0);

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);

        // Should only contain the settlement address
        assertEq(result, abi.encodePacked(settlement));
    }

    function test_verifyAndBuildWrapperData_SingleWrapper() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1),
            data: hex"deadbeef"
        });

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);

        // Should contain: data[0] + settlement
        bytes memory expected = abi.encodePacked(hex"deadbeef", settlement);
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_MultipleWrappers() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](3);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1),
            data: hex"deadbeef"
        });
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper2),
            data: hex"cafebabe12345678"
        });
        wrapperCalls[2] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper3),
            data: hex""
        });

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);

        // Should contain: data[0] + target[1] + data[1] + target[2] + data[2] + settlement
        bytes memory expected = abi.encodePacked(
            hex"deadbeef",
            address(wrapper2),
            hex"cafebabe12345678",
            address(wrapper3),
            hex"",
            settlement
        );
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_RevertsOnNotAWrapper() public {
        address notAWrapper = makeAddr("notAWrapper");

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: notAWrapper,
            data: hex""
        });

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.NotAWrapper.selector, 0, notAWrapper, address(wrapperAuth)));
        helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnNotAWrapper_SecondWrapper() public {
        address notAWrapper = makeAddr("notAWrapper");

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](2);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1),
            data: hex"deadbeef"
        });
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({
            target: notAWrapper,
            data: hex""
        });

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.NotAWrapper.selector, 1, notAWrapper, address(wrapperAuth)));
        helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataNotFullyConsumed() public {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1), // Consumes 4 bytes
            data: hex"deadbeefcafe" // 6 bytes, but wrapper only consumes 4
        });

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataNotFullyConsumed.selector, 0, hex"cafe"));
        helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataMalformed() public {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(brokenWrapper),
            data: hex"deadbeef"
        });

        vm.expectRevert();
        helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnSettlementContractShouldNotBeSolver() public {
        // Add settlement as a solver (which should not be allowed)
        solverAuth.addSolver(settlement);

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1),
            data: hex"deadbeef"
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                CowWrapperHelpers.SettlementContractShouldNotBeSolver.selector,
                settlement,
                address(solverAuth)
            )
        );
        helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);
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

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);

        // Should contain: data[0] + target[1] + data[1] + settlement
        bytes memory expected = abi.encodePacked(hex"", address(wrapper3), hex"", settlement);
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

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls, settlement);

        bytes memory expected = abi.encodePacked(
            hex"",
            address(wrapper1),
            hex"deadbeef",
            address(wrapper2),
            hex"cafebabe12345678",
            settlement
        );
        assertEq(result, expected);
    }

    function test_immutableAuthenticators() public view {
        assertEq(address(helpers.WRAPPER_AUTHENTICATOR()), address(wrapperAuth));
        assertEq(address(helpers.SOLVER_AUTHENTICATOR()), address(solverAuth));
    }
}
