// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapper, ICowSettlement, ICowAuthentication} from "../src/vendor/CowWrapper.sol";
import {IERC20, GPv2Trade, GPv2Interaction} from "cow/GPv2Settlement.sol";
import {EmptyWrapper} from "./EmptyWrapper.sol";

import {CowWrapperHelpers} from "./helpers/CowWrapperHelpers.sol";

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
        IERC20[] calldata,
        uint256[] calldata,
        GPv2Trade.Data[] calldata,
        GPv2Interaction.Data[][3] calldata
    ) external {}
}

// Test wrapper that exposes internal functions
contract TestWrapper is CowWrapper {
    string public override name = "Test Wrapper";

    constructor(ICowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData) internal override {
        _internalSettle(settleData, remainingWrapperData);
    }

    function exposedInternalSettle(bytes calldata settleData, bytes calldata wrapperData) external {
        _internalSettle(settleData, wrapperData);
    }
}

contract CowWrapperTest is Test {
    MockAuthentication public authenticator;
    MockSettlement public mockSettlement;
    address public solver;

    TestWrapper public testWrapper;
    EmptyWrapper private wrapper1;
    EmptyWrapper private wrapper2;
    EmptyWrapper private wrapper3;

    function setUp() public {
        // Deploy mock contracts
        authenticator = new MockAuthentication();
        mockSettlement = new MockSettlement(ICowAuthentication(address(authenticator)));

        solver = makeAddr("solver");
        // Add solver to the authenticator
        authenticator.addSolver(solver);

        // Create test wrapper and three EmptyWrapper instances with the settlement contract
        testWrapper = new TestWrapper(ICowSettlement(address(mockSettlement)));
        wrapper1 = new EmptyWrapper(ICowSettlement(address(mockSettlement)));
        wrapper2 = new EmptyWrapper(ICowSettlement(address(mockSettlement)));
        wrapper3 = new EmptyWrapper(ICowSettlement(address(mockSettlement)));

        // Add all wrappers as solvers
        authenticator.addSolver(address(testWrapper));
        authenticator.addSolver(address(wrapper1));
        authenticator.addSolver(address(wrapper2));
        authenticator.addSolver(address(wrapper3));
    }

    function _emptyInteractions() private pure returns (GPv2Interaction.Data[][3] memory) {
        return [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];
    }

    function _createSimpleSettleData(uint256 tokenCount) private returns (bytes memory) {
        IERC20[] memory tokens = new IERC20[](tokenCount);
        uint256[] memory clearingPrices = new uint256[](tokenCount);
        for (uint256 i = 0; i < tokenCount; i++) {
            tokens[i] = IERC20(makeAddr(string(abi.encodePacked("Settle Token #", vm.toString(i + 1)))));
            clearingPrices[i] = 100 * (i + 1);
        }
        return abi.encodeWithSelector(
            ICowSettlement.settle.selector, tokens, clearingPrices, new GPv2Trade.Data[](0), _emptyInteractions()
        );
    }

    function test_internalSettle_CallsWrapperAndThenNextSettlement() public {
        bytes memory settleData = abi.encodePacked(_createSimpleSettleData(1), hex"123456");
        bytes memory secondCallWrapperData = hex"0003098765";
        bytes memory wrapperData = abi.encodePacked(hex"00021234", address(testWrapper), secondCallWrapperData);

        // the wrapper gets called exactly twice (once below and again inside the wrapper data calling self)
        vm.expectCall(address(testWrapper), 0, abi.encodeWithSelector(testWrapper.wrappedSettle.selector), 2);

        // verify the internal wrapper call data
        vm.expectCall(
            address(testWrapper),
            abi.encodeWithSelector(testWrapper.wrappedSettle.selector, settleData, secondCallWrapperData)
        );

        // the settlement contract gets called once after wrappers (including the surplus data at the end)
        vm.expectCall(address(mockSettlement), 0, settleData, 1);

        vm.prank(solver);
        testWrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWithNotASolver() public {
        bytes memory settleData = _createSimpleSettleData(0);
        address notASolver = makeAddr("notASolver");

        // Should revert when called by non-solver
        vm.prank(notASolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, notASolver));
        testWrapper.wrappedSettle(settleData, hex"");
    }

    function test_wrappedSettle_RevertsOnInvalidSettleSelector() public {
        bytes memory settleData = abi.encodePacked(bytes4(0xdeadbeef), hex"1234");
        bytes memory wrapperData = hex"0000"; // Empty wrapper data, goes straight to settlement
        vm.prank(solver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.InvalidSettleData.selector, settleData));
        testWrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_integration_ThreeWrappersChained() public {
        // Set up a more sophisticated settlement call to make sure it all gets through as expected.
        CowWrapperHelpers.SettleCall memory settlement;
        settlement.tokens = new address[](2);
        settlement.tokens[0] = address(0x1);
        settlement.tokens[1] = address(0x2);
        settlement.clearingPrices = new uint256[](2);
        settlement.clearingPrices[0] = 100;
        settlement.clearingPrices[1] = 200;

        settlement.trades = new ICowSettlement.Trade[](1);
        settlement.trades[0] = ICowSettlement.Trade({
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

        settlement.interactions = [
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](0),
            new ICowSettlement.Interaction[](0)
        ];

        // Build the chained wrapper data:
        // solver -> wrapper1 -> wrapper2 -> wrapper1 -> wrapper3 -> mockSettlement
        address[] memory wrappers = new address[](4);
        wrappers[0] = address(wrapper1);
        wrappers[1] = address(wrapper2);
        wrappers[2] = address(wrapper1);
        wrappers[3] = address(wrapper3);

        bytes[] memory datas = new bytes[](4);

        datas[2] = hex"828348";

        (address target, bytes memory fullCalldata) =
            CowWrapperHelpers.encodeWrapperCall(wrappers, datas, address(mockSettlement), settlement);

        // all the wrappers gets called, with wrapper 1 called twice
        vm.expectCall(address(wrapper1), 0, abi.encodeWithSelector(testWrapper.wrappedSettle.selector), 2);
        vm.expectCall(address(wrapper2), 0, abi.encodeWithSelector(testWrapper.wrappedSettle.selector), 1);
        vm.expectCall(address(wrapper3), 0, abi.encodeWithSelector(testWrapper.wrappedSettle.selector), 1);

        // the settlement gets called with the full data
        vm.expectCall(address(mockSettlement), new bytes(0));

        // Call wrapper1 as the solver
        vm.prank(solver);
        (bool success,) = target.call(fullCalldata);
        assertTrue(success, "Chained wrapper call should succeed");
    }
}
