// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapper, CowSettlement, CowAuthentication} from "../src/vendor/CowWrapper.sol";
import {IERC20, GPv2Trade, GPv2Interaction} from "cow/GPv2Settlement.sol";
import {EmptyWrapper} from "./EmptyWrapper.sol";

import {CowWrapperHelpers} from "./helpers/CowWrapperHelpers.sol";

import "forge-std/console.sol";

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
    struct SettleCall {
        IERC20[] tokens;
        uint256[] clearingPrices;
        GPv2Trade.Data[] trades;
        bytes origData;
    }

    SettleCall[] public settleCalls;
    CowAuthentication private immutable _authenticator;

    constructor(CowAuthentication authenticator_) {
        _authenticator = authenticator_;
    }

    function authenticator() external view returns (CowAuthentication) {
        return _authenticator;
    }

    function settle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external {
        SettleCall storage call_ = settleCalls.push();
        call_.tokens = tokens;
        call_.clearingPrices = clearingPrices;

        for (uint256 i = 0; i < trades.length; i++) {
            call_.trades.push(trades[i]);
        }

        call_.origData = msg.data;
    }

    function getSettleCallCount() external view returns (uint256) {
        return settleCalls.length;
    }

    function getLastSettleCall()
        external
        view
        returns (uint256 tokenCount, uint256 priceCount, uint256 tradeCount, bytes memory origData)
    {
        require(settleCalls.length > 0, "No settle calls");
        SettleCall storage lastCall = settleCalls[settleCalls.length - 1];
        return (lastCall.tokens.length, lastCall.clearingPrices.length, lastCall.trades.length, lastCall.origData);
    }
}

// Test wrapper that exposes internal functions
contract TestWrapper is CowWrapper {
    string public constant name = "Test Wrapper";

    // Track _wrap calls
    struct WrapCall {
        bytes settleData;
        bytes wrapperData;
    }

    WrapCall[] public wrapCalls;

    constructor(CowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        // Record the wrap call
        WrapCall storage call_ = wrapCalls.push();
        call_.settleData = settleData;
        call_.wrapperData = wrapperData;

        // Call internal settle
        _internalSettle(settleData, remainingWrapperData);
    }

    function exposed_internalSettle(bytes calldata settleData, bytes calldata wrapperData) external {
        _internalSettle(settleData, wrapperData);
    }

    function getWrapCallCount() external view returns (uint256) {
        return wrapCalls.length;
    }

    function getWrapCall(uint256 index) external view returns (bytes memory settleData, bytes memory wrapperData) {
        return (wrapCalls[index].settleData, wrapCalls[index].wrapperData);
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
        mockSettlement = new MockSettlement(CowAuthentication(address(authenticator)));

        solver = makeAddr("solver");
        // Add solver to the authenticator
        authenticator.addSolver(solver);

        // Create test wrapper and three EmptyWrapper instances with the settlement contract
        testWrapper = new TestWrapper(CowSettlement(address(mockSettlement)));
        wrapper1 = new EmptyWrapper(CowSettlement(address(mockSettlement)));
        wrapper2 = new EmptyWrapper(CowSettlement(address(mockSettlement)));
        wrapper3 = new EmptyWrapper(CowSettlement(address(mockSettlement)));

        // Add all wrappers as solvers
        authenticator.addSolver(address(testWrapper));
        authenticator.addSolver(address(wrapper1));
        authenticator.addSolver(address(wrapper2));
        authenticator.addSolver(address(wrapper3));
    }

    function _emptyInteractions() private pure returns (GPv2Interaction.Data[][3] memory) {
        return [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];
    }

    function _createSimpleSettleData(uint256 tokenCount) private pure returns (bytes memory) {
        IERC20[] memory tokens = new IERC20[](tokenCount);
        uint256[] memory clearingPrices = new uint256[](tokenCount);
        for (uint256 i = 0; i < tokenCount; i++) {
            tokens[i] = IERC20(address(uint160(i + 1)));
            clearingPrices[i] = 100 * (i + 1);
        }
        return abi.encodeWithSelector(
            CowSettlement.settle.selector, tokens, clearingPrices, new GPv2Trade.Data[](0), _emptyInteractions()
        );
    }

    function test_wrap_ReceivesCorrectParameters() public {
        bytes memory customWrapperData = hex"deadbeef";
        bytes memory settleData = _createSimpleSettleData(1);
        // wrapperData is just custom data - no settlement address needed
        bytes memory wrapperData = abi.encodePacked(uint16(customWrapperData.length), customWrapperData);

        vm.prank(solver);
        testWrapper.wrappedSettle(settleData, wrapperData);

        assertEq(testWrapper.getWrapCallCount(), 1);
        (bytes memory recordedSettleData, bytes memory recordedWrapperData) = testWrapper.getWrapCall(0);
        assertGt(recordedSettleData.length, 0);
        assertEq(recordedWrapperData, customWrapperData);
    }

    function test_internalSettle_CallsNextSettlement() public {
        bytes memory settleData = abi.encodePacked(_createSimpleSettleData(1), hex"123456");
        // Empty wrapperData means call the static SETTLEMENT contract
        bytes memory wrapperData = hex"0000";

        vm.prank(solver);
        testWrapper.wrappedSettle(settleData, wrapperData);

        assertEq(mockSettlement.getSettleCallCount(), 1);
        (uint256 tokenCount, uint256 priceCount, uint256 tradeCount, bytes memory origData) = mockSettlement.getLastSettleCall();
        assertEq(tokenCount, 1);
        assertEq(priceCount, 1);
        assertEq(tradeCount, 0);
        assertEq(origData, settleData);
    }

    function test_wrappedSettle_RevertsWithNotASolver() public {
        bytes memory settleData = _createSimpleSettleData(0);
        address notASolver = makeAddr("notASolver");

        // Should revert when called by non-solver
        vm.prank(notASolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, notASolver));
        testWrapper.wrappedSettle(settleData, hex"");
    }

    function test_integration_ThreeWrappersChained() public {
        CowWrapperHelpers.SettleCall memory settlement;
        settlement.tokens = new address[](2);
        settlement.tokens[0] = address(0x1);
        settlement.tokens[1] = address(0x2);
        settlement.clearingPrices = new uint256[](2);
        settlement.clearingPrices[0] = 100;
        settlement.clearingPrices[1] = 200;

        settlement.trades = new CowSettlement.CowTradeData[](1);
        settlement.trades[0] = CowSettlement.CowTradeData({
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
            new CowSettlement.CowInteractionData[](0),
            new CowSettlement.CowInteractionData[](0),
            new CowSettlement.CowInteractionData[](0)
        ];

        // Build the chained wrapper data:
        // solver -> wrapper1 -> wrapper2 -> wrapper3 -> mockSettlement
        address[] memory wrappers = new address[](3);
        wrappers[0] = address(wrapper1);
        wrappers[1] = address(wrapper2);
        wrappers[2] = address(wrapper3);

        (address target, bytes memory fullCalldata) =
            CowWrapperHelpers.encodeWrapperCall(wrappers, new bytes[](3), address(mockSettlement), settlement);

        // Call wrapper1 as the solver
        vm.prank(solver);
        (bool success,) = target.call(fullCalldata);
        assertTrue(success, "Chained wrapper call should succeed");

        // Verify that mockSettlement was called
        assertEq(mockSettlement.getSettleCallCount(), 1, "MockSettlement should be called once");

        // Verify the settlement received the correct parameters
        (uint256 tokenCount, uint256 priceCount, uint256 tradeCount,) = mockSettlement.getLastSettleCall();
        assertEq(tokenCount, 2, "Should have 2 tokens");
        assertEq(priceCount, 2, "Should have 2 prices");
        assertEq(tradeCount, 1, "Should have 1 trade");
    }
}
