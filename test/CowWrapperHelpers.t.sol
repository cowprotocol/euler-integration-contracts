// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapperHelpers} from "../src/vendor/CowWrapperHelpers.sol";
import {CowWrapper, GPv2Authentication, ICowWrapper} from "../src/vendor/CowWrapper.sol";

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

    constructor(GPv2Authentication authenticator_, uint256 consumeBytes_) CowWrapper(authenticator_) {
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
    constructor(GPv2Authentication authenticator_) CowWrapper(authenticator_) {}

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
        helpers = new CowWrapperHelpers(GPv2Authentication(address(wrapperAuth)), GPv2Authentication(address(solverAuth)));

        settlement = makeAddr("settlement");

        // Create mock wrappers
        wrapper1 = new MockWrapper(GPv2Authentication(address(wrapperAuth)), 4);
        wrapper2 = new MockWrapper(GPv2Authentication(address(wrapperAuth)), 8);
        wrapper3 = new MockWrapper(GPv2Authentication(address(wrapperAuth)), 0);
        brokenWrapper = new BrokenWrapper(GPv2Authentication(address(wrapperAuth)));

        // Add wrappers as solvers
        wrapperAuth.addSolver(address(wrapper1));
        wrapperAuth.addSolver(address(wrapper2));
        wrapperAuth.addSolver(address(wrapper3));
        wrapperAuth.addSolver(address(brokenWrapper));
    }

    function test_verifyAndBuildWrapperData_EmptyArrays() public view {
        address[] memory wrappers = new address[](0);
        bytes[] memory wrapperDatas = new bytes[](0);

        bytes memory result = helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);

        // Should only contain the settlement address
        assertEq(result, abi.encodePacked(settlement));
    }

    function test_verifyAndBuildWrapperData_SingleWrapper() public view {
        address[] memory wrappers = new address[](1);
        wrappers[0] = address(wrapper1);

        bytes[] memory wrapperDatas = new bytes[](1);
        wrapperDatas[0] = hex"deadbeef";

        bytes memory result = helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);

        // Should contain: wrapperData[0] + settlement
        bytes memory expected = abi.encodePacked(hex"deadbeef", settlement);
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_MultipleWrappers() public view {
        address[] memory wrappers = new address[](3);
        wrappers[0] = address(wrapper1);
        wrappers[1] = address(wrapper2);
        wrappers[2] = address(wrapper3);

        bytes[] memory wrapperDatas = new bytes[](3);
        wrapperDatas[0] = hex"deadbeef";
        wrapperDatas[1] = hex"cafebabe12345678";
        wrapperDatas[2] = hex"";

        bytes memory result = helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);

        // Should contain: wrapperData[0] + wrapper[1] + wrapperData[1] + wrapper[2] + wrapperData[2] + settlement
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

    function test_verifyAndBuildWrapperData_RevertsOnInvalidInputLengths() public {
        address[] memory wrappers = new address[](2);
        wrappers[0] = address(wrapper1);
        wrappers[1] = address(wrapper2);

        bytes[] memory wrapperDatas = new bytes[](1);
        wrapperDatas[0] = hex"deadbeef";

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.InvalidInputLengths.selector, 2, 1));
        helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnNotAWrapper() public {
        address notAWrapper = makeAddr("notAWrapper");

        address[] memory wrappers = new address[](1);
        wrappers[0] = notAWrapper;

        bytes[] memory wrapperDatas = new bytes[](1);
        wrapperDatas[0] = hex"";

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.NotAWrapper.selector, 0, notAWrapper, address(wrapperAuth)));
        helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnNotAWrapper_SecondWrapper() public {
        address notAWrapper = makeAddr("notAWrapper");

        address[] memory wrappers = new address[](2);
        wrappers[0] = address(wrapper1);
        wrappers[1] = notAWrapper;

        bytes[] memory wrapperDatas = new bytes[](2);
        wrapperDatas[0] = hex"deadbeef";
        wrapperDatas[1] = hex"";

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.NotAWrapper.selector, 1, notAWrapper, address(wrapperAuth)));
        helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataNotFullyConsumed() public {
        address[] memory wrappers = new address[](1);
        wrappers[0] = address(wrapper1); // Consumes 4 bytes

        bytes[] memory wrapperDatas = new bytes[](1);
        wrapperDatas[0] = hex"deadbeefcafe"; // 6 bytes, but wrapper only consumes 4

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.WrapperDataNotFullyConsumed.selector, 0, hex"cafe"));
        helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnWrapperDataMalformed() public {
        address[] memory wrappers = new address[](1);
        wrappers[0] = address(brokenWrapper);

        bytes[] memory wrapperDatas = new bytes[](1);
        wrapperDatas[0] = hex"deadbeef";

        vm.expectRevert();
        helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);
    }

    function test_verifyAndBuildWrapperData_RevertsOnSettlementContractShouldNotBeSolver() public {
        // Add settlement as a solver (which should not be allowed)
        solverAuth.addSolver(settlement);

        address[] memory wrappers = new address[](1);
        wrappers[0] = address(wrapper1);

        bytes[] memory wrapperDatas = new bytes[](1);
        wrapperDatas[0] = hex"deadbeef";

        vm.expectRevert(
            abi.encodeWithSelector(
                CowWrapperHelpers.SettlementContractShouldNotBeSolver.selector,
                settlement,
                address(solverAuth)
            )
        );
        helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);
    }

    function test_verifyAndBuildWrapperData_EmptyWrapperData() public view {
        address[] memory wrappers = new address[](2);
        wrappers[0] = address(wrapper3); // Consumes 0 bytes
        wrappers[1] = address(wrapper3); // Consumes 0 bytes

        bytes[] memory wrapperDatas = new bytes[](2);
        wrapperDatas[0] = hex"";
        wrapperDatas[1] = hex"";

        bytes memory result = helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);

        // Should contain: "" + wrapper[1] + "" + settlement
        bytes memory expected = abi.encodePacked(hex"", address(wrapper3), hex"", settlement);
        assertEq(result, expected);
    }

    function test_verifyAndBuildWrapperData_MixedWrapperDataSizes() public view {
        address[] memory wrappers = new address[](3);
        wrappers[0] = address(wrapper3); // Consumes 0 bytes
        wrappers[1] = address(wrapper1); // Consumes 4 bytes
        wrappers[2] = address(wrapper2); // Consumes 8 bytes

        bytes[] memory wrapperDatas = new bytes[](3);
        wrapperDatas[0] = hex"";
        wrapperDatas[1] = hex"deadbeef";
        wrapperDatas[2] = hex"cafebabe12345678";

        bytes memory result = helpers.verifyAndBuildWrapperData(wrappers, wrapperDatas, settlement);

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
