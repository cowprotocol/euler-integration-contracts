// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapperHelpers} from "../src/vendor/CowWrapperHelpers.sol";
import {CowWrapper, CowAuthentication, CowSettlement} from "../src/vendor/CowWrapper.sol";

contract MockAuthenticator {
    mapping(address => bool) public solvers;

    function addSolver(address solver) external {
        solvers[solver] = true;
    }

    function isSolver(address solver) external view returns (bool) {
        return solvers[solver];
    }
}

contract MockSettlement {
    CowAuthentication private immutable AUTHENTICATOR;

    constructor(CowAuthentication authenticator_) {
        AUTHENTICATOR = authenticator_;
    }

    function authenticator() external view returns (CowAuthentication) {
        return AUTHENTICATOR;
    }
}

contract MockWrapper is CowWrapper {
    string constant public name = "Mock Wrapper";
    uint256 public consumeBytes;

    constructor(CowSettlement settlement_, uint256 consumeBytes_) CowWrapper(settlement_) {
        consumeBytes = consumeBytes_;
    }

    function _wrap(bytes calldata, bytes calldata, bytes calldata) internal override {
        // Not used in these tests
    }

    function parseWrapperData(bytes calldata wrapperData) external view override returns (bytes calldata remainingWrapperData) {
        return wrapperData[consumeBytes:];
    }
}

contract BrokenWrapper is CowWrapper {
    string public constant name = "Broken Wrapper";
    constructor(CowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata, bytes calldata, bytes calldata) internal override {
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
    MockSettlement mockSettlement;

    MockWrapper wrapper1;
    MockWrapper wrapper2;
    MockWrapper wrapper3;
    BrokenWrapper brokenWrapper;

    function setUp() public {
        wrapperAuth = new MockAuthenticator();
        solverAuth = new MockAuthenticator();
        helpers = new CowWrapperHelpers(CowAuthentication(address(wrapperAuth)), CowAuthentication(address(solverAuth)));

        mockSettlement = new MockSettlement(CowAuthentication(address(wrapperAuth)));

        // Create mock wrappers
        wrapper1 = new MockWrapper(CowSettlement(address(mockSettlement)), 4);
        wrapper2 = new MockWrapper(CowSettlement(address(mockSettlement)), 8);
        wrapper3 = new MockWrapper(CowSettlement(address(mockSettlement)), 0);
        brokenWrapper = new BrokenWrapper(CowSettlement(address(mockSettlement)));

        // Add wrappers as solvers
        wrapperAuth.addSolver(address(wrapper1));
        wrapperAuth.addSolver(address(wrapper2));
        wrapperAuth.addSolver(address(wrapper3));
        wrapperAuth.addSolver(address(brokenWrapper));
    }

    function test_verifyAndBuildWrapperData_EmptyArrays() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](0);

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should be empty
        assertEq(result, hex"");
    }

    function test_verifyAndBuildWrapperData_SingleWrapper() public view {
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1),
            data: hex"deadbeef"
        });

        bytes memory result = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // Should contain: data[0] only (no settlement appended)
        bytes memory expected = abi.encodePacked(uint16(4), hex"deadbeef");
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
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: notAWrapper,
            data: hex""
        });

        vm.expectRevert(abi.encodeWithSelector(CowWrapperHelpers.NotAWrapper.selector, 0, notAWrapper, address(wrapperAuth)));
        helpers.verifyAndBuildWrapperData(wrapperCalls);
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
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(brokenWrapper),
            data: hex"deadbeef"
        });

        vm.expectRevert();
        helpers.verifyAndBuildWrapperData(wrapperCalls);
    }

    function test_verifyAndBuildWrapperData_RevertsOnSettlementContractShouldNotBeSolver() public {
        // Add settlement as a solver (which should not be allowed)
        solverAuth.addSolver(address(mockSettlement));

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1),
            data: hex"deadbeef"
        });

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

        // Should contain: data[0] + target[1] + data[1] (no settlement)
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

    function test_immutableAuthenticators() public view {
        assertEq(address(helpers.WRAPPER_AUTHENTICATOR()), address(wrapperAuth));
        assertEq(address(helpers.SOLVER_AUTHENTICATOR()), address(solverAuth));
    }
}
