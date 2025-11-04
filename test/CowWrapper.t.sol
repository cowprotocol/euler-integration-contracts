// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapper, ICowSettlement, ICowAuthentication} from "../src/CowWrapper.sol";
import {EmptyWrapper} from "./EmptyWrapper.sol";

import {CowWrapperHelpers} from "../src/CowWrapperHelpers.sol";

contract MockAuthentication {
    mapping(address => bool) public solvers;

    function addSolver(address solver) external {
        solvers[solver] = true;
    }

    function isSolver(address solver) external view returns (bool) {
        return solvers[solver];
    }
}

contract MockSettlement {
    ICowAuthentication private immutable AUTHENTICATOR;

    constructor(ICowAuthentication authenticator_) {
        AUTHENTICATOR = authenticator_;
    }

    function authenticator() external view returns (ICowAuthentication) {
        return AUTHENTICATOR;
    }

    function settle(
        address[] calldata,
        uint256[] calldata,
        ICowSettlement.Trade[] calldata,
        ICowSettlement.Interaction[][3] calldata
    ) external {}
}

// Test wrapper that exposes internal functions
contract TestWrapper is CowWrapper {
    string public override name = "Test Wrapper";

    constructor(ICowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData) internal override {
        _next(settleData, remainingWrapperData);
    }

    function parseWrapperData(bytes calldata wrapperData)
        external
        pure
        override
        returns (bytes calldata remainingWrapperData)
    {
        // always pretend to consume all the wrapper data
        return wrapperData[0:0];
    }
}

contract CowWrapperTest is Test {
    MockAuthentication public authenticator;
    MockSettlement public mockSettlement;
    CowWrapperHelpers public helpers;
    address public solver;

    TestWrapper private wrapper1;
    TestWrapper private wrapper2;
    TestWrapper private wrapper3;

    function setUp() public {
        // Deploy mock contracts
        authenticator = new MockAuthentication();
        mockSettlement = new MockSettlement(ICowAuthentication(address(authenticator)));
        helpers =
            new CowWrapperHelpers(ICowAuthentication(address(authenticator)), ICowAuthentication(address(authenticator)));

        solver = makeAddr("solver");
        // Add solver to the authenticator
        authenticator.addSolver(solver);

        // Create test wrappers
        wrapper1 = new TestWrapper(ICowSettlement(address(mockSettlement)));
        wrapper2 = new TestWrapper(ICowSettlement(address(mockSettlement)));
        wrapper3 = new TestWrapper(ICowSettlement(address(mockSettlement)));

        // Add all wrappers as solvers
        authenticator.addSolver(address(wrapper1));
        authenticator.addSolver(address(wrapper2));
        authenticator.addSolver(address(wrapper3));
    }

    function _emptyInteractions() private pure returns (ICowSettlement.Interaction[][3] memory) {
        return [new ICowSettlement.Interaction[](0), new ICowSettlement.Interaction[](0), new ICowSettlement.Interaction[](0)];
    }

    function _createSimpleSettleData(uint256 tokenCount) private returns (bytes memory) {
        address[] memory tokens = new address[](tokenCount);
        uint256[] memory clearingPrices = new uint256[](tokenCount);
        for (uint256 i = 0; i < tokenCount; i++) {
            tokens[i] = makeAddr(string(abi.encodePacked("Settle Token #", vm.toString(i + 1))));
            clearingPrices[i] = 100 * (i + 1);
        }
        return abi.encodeWithSelector(
            ICowSettlement.settle.selector, tokens, clearingPrices, new ICowSettlement.Trade[](0), _emptyInteractions()
        );
    }

    function test_next_CallsWrapperAndThenNextSettlement() public {
        bytes memory settleData = abi.encodePacked(_createSimpleSettleData(1), hex"123456");
        bytes memory secondCallWrapperData = hex"0003098765";
        bytes memory wrapperData = abi.encodePacked(hex"00021234", address(wrapper1), secondCallWrapperData);

        // the wrapper gets called exactly twice (once below and again inside the wrapper data calling self)
        vm.expectCall(address(wrapper1), 0, abi.encodeWithSelector(wrapper1.wrappedSettle.selector), 2);

        // verify the internal wrapper call data
        vm.expectCall(
            address(wrapper1),
            abi.encodeWithSelector(wrapper1.wrappedSettle.selector, settleData, secondCallWrapperData)
        );

        // the settlement contract gets called once after wrappers (including the surplus data at the end)
        vm.expectCall(address(mockSettlement), 0, settleData, 1);

        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWithNotASolver() public {
        bytes memory settleData = _createSimpleSettleData(0);
        address notASolver = makeAddr("notASolver");

        // Should revert when called by non-solver
        vm.prank(notASolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, notASolver));
        wrapper1.wrappedSettle(settleData, hex"");
    }

    function test_wrappedSettle_RevertsOnInvalidSettleSelector() public {
        bytes memory settleData = abi.encodePacked(bytes4(0xdeadbeef), hex"1234");
        bytes memory wrapperData = hex"0000"; // Empty wrapper data, goes straight to settlement
        vm.prank(solver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.InvalidSettleData.selector, settleData));
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_integration_ThreeWrappersChained() public {
        address[] memory tokens = new address[](2);
        tokens[0] = address(0x1);
        tokens[1] = address(0x2);

        uint256[] memory clearingPrices = new uint256[](2);
        clearingPrices[0] = 100;
        clearingPrices[1] = 200;

        ICowSettlement.Trade[] memory trades = new ICowSettlement.Trade[](1);
        trades[0] = ICowSettlement.Trade({
            sellTokenIndex: 0,
            buyTokenIndex: 1,
            receiver: address(0x123),
            sellAmount: 1000,
            buyAmount: 900,
            validTo: uint32(block.timestamp + 1000),
            appData: bytes32(uint256(1)),
            feeAmount: 10,
            flags: 0,
            executedAmount: 0,
            signature: hex"aabbccddee"
        });

        bytes memory settleData = abi.encodeCall(ICowSettlement.settle, (tokens, clearingPrices, trades, _emptyInteractions()));

        // Build the chained wrapper data:
        // solver -> wrapper1 -> wrapper2 -> wrapper1 -> wrapper3 -> mockSettlement
        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](4);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex""});
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({target: address(wrapper2), data: hex""});
        wrapperCalls[2] = CowWrapperHelpers.WrapperCall({target: address(wrapper1), data: hex"828348"});
        wrapperCalls[3] = CowWrapperHelpers.WrapperCall({target: address(wrapper3), data: hex""});

        bytes memory wrapperData = helpers.verifyAndBuildWrapperData(wrapperCalls);

        // all the wrappers gets called, with wrapper 1 called twice
        vm.expectCall(address(wrapper1), 0, abi.encodeWithSelector(wrapper1.wrappedSettle.selector), 2);
        vm.expectCall(address(wrapper2), 0, abi.encodeWithSelector(wrapper2.wrappedSettle.selector), 1);
        vm.expectCall(address(wrapper3), 0, abi.encodeWithSelector(wrapper3.wrappedSettle.selector), 1);

        // the settlement gets called with the full data
        vm.expectCall(address(mockSettlement), new bytes(0));

        // Call wrapper1 as the solver
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }
}
