// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapper, CowSettlement, CowAuthentication} from "../src/vendor/CowWrapper.sol";
import {IERC20, GPv2Trade, GPv2Interaction} from "cow/GPv2Settlement.sol";
import {EmptyWrapper} from "./EmptyWrapper.sol";

import {CowWrapperHelpers} from "../src/vendor/CowWrapperHelpers.sol";

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
        bytes additionalData;
    }

    SettleCall[] public settleCalls;
    CowAuthentication private immutable AUTHENTICATOR;

    constructor(CowAuthentication authenticator_) {
        AUTHENTICATOR = authenticator_;
    }

    function authenticator() external view returns (CowAuthentication) {
        return AUTHENTICATOR;
    }

    function settle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata
    ) external {
        SettleCall storage call_ = settleCalls.push();
        call_.tokens = tokens;
        call_.clearingPrices = clearingPrices;

        for (uint256 i = 0; i < trades.length; i++) {
            call_.trades.push(trades[i]);
        }

        // Extract any additional data appended after standard calldata
        uint256 expectedLength = 4 + 4 * 32;
        expectedLength += 32 + tokens.length * 32;
        expectedLength += 32 + clearingPrices.length * 32;
        expectedLength += 32;
        for (uint256 i = 0; i < trades.length; i++) {
            expectedLength += 9 * 32 + 32 + trades[i].signature.length;
        }
        expectedLength += 32;
        expectedLength += 3 * 32;
        expectedLength += 3 * 32;

        if (msg.data.length > expectedLength) {
            call_.additionalData = msg.data[expectedLength:];
        }
    }

    function getSettleCallCount() external view returns (uint256) {
        return settleCalls.length;
    }

    function getLastSettleCall()
        external
        view
        returns (uint256 tokenCount, uint256 priceCount, uint256 tradeCount, bytes memory additionalData)
    {
        require(settleCalls.length > 0, "No settle calls");
        SettleCall storage lastCall = settleCalls[settleCalls.length - 1];
        return (lastCall.tokens.length, lastCall.clearingPrices.length, lastCall.trades.length, lastCall.additionalData);
    }
}

// Test wrapper that exposes internal functions
contract TestWrapper is CowWrapper {
    // Track _wrap calls
    struct WrapCall {
        bytes settleData;
        bytes wrapperData;
    }

    WrapCall[] public wrapCalls;

    uint256 public skipWrappedData;

    constructor(CowSettlement settlement_) CowWrapper(settlement_) {}

    function _wrap(bytes calldata settleData, bytes calldata wrapperData) internal override {
        // Record the wrap call
        WrapCall storage call_ = wrapCalls.push();
        call_.settleData = settleData;
        call_.wrapperData = wrapperData[0:skipWrappedData];

        // Call internal settle
        _internalSettle(settleData, wrapperData[skipWrappedData:]);
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

    function setSkipWrappedData(uint256 value) external {
        skipWrappedData = value;
    }

    function parseWrapperData(bytes calldata wrapperData) external view override returns (bytes calldata remainingWrapperData) {
        // TestWrapper consumes skipWrappedData bytes
        return wrapperData[skipWrappedData:];
    }
}

contract CowWrapperTest is Test {
    MockAuthentication public authenticator;
    MockSettlement public mockSettlement;
    CowWrapperHelpers public helpers;
    address public solver;

    TestWrapper public testWrapper;
    EmptyWrapper private wrapper1;
    EmptyWrapper private wrapper2;
    EmptyWrapper private wrapper3;

    function setUp() public {
        // Deploy mock contracts
        authenticator = new MockAuthentication();
        mockSettlement = new MockSettlement(CowAuthentication(address(authenticator)));
        helpers = new CowWrapperHelpers(CowAuthentication(address(authenticator)), CowAuthentication(address(authenticator)));

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

    function test_wrap_ReceivesCorrectParameters() public {
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(address(0x1));

        uint256[] memory clearingPrices = new uint256[](1);
        clearingPrices[0] = 100;

        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory customWrapperData = hex"deadbeef";

        bytes memory settleData =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        // wrapperData is just custom data - no settlement address needed
        bytes memory wrapperData = customWrapperData;

        testWrapper.setSkipWrappedData(customWrapperData.length);

        vm.prank(solver);
        testWrapper.wrappedSettle(settleData, wrapperData);
        testWrapper.setSkipWrappedData(0);

        assertEq(testWrapper.getWrapCallCount(), 1);
        (bytes memory recordedSettleData, bytes memory recordedWrapperData) = testWrapper.getWrapCall(0);
        assertGt(recordedSettleData.length, 0);
        assertEq(recordedWrapperData, customWrapperData);
    }

    function test_internalSettle_CallsNextSettlement() public {
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(address(0x1));

        uint256[] memory clearingPrices = new uint256[](1);
        clearingPrices[0] = 100;

        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory settleData =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        // Empty wrapperData means call the static SETTLEMENT contract
        bytes memory wrapperData = hex"";

        vm.prank(solver);
        testWrapper.wrappedSettle(settleData, wrapperData);

        assertEq(mockSettlement.getSettleCallCount(), 1);
        (uint256 tokenCount, uint256 priceCount, uint256 tradeCount,) = mockSettlement.getLastSettleCall();
        assertEq(tokenCount, 1);
        assertEq(priceCount, 1);
        assertEq(tradeCount, 0);
    }

    function test_wrappedSettle_RevertsWithNotASolver() public {
        IERC20[] memory tokens = new IERC20[](0);
        uint256[] memory clearingPrices = new uint256[](0);
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory settleData =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        bytes memory wrapperData = hex"";

        address notASolver = makeAddr("notASolver");

        // Should revert when called by non-solver
        vm.prank(notASolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, notASolver));
        testWrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_integration_ThreeWrappersChained() public {
        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(address(0x1));
        tokens[1] = IERC20(address(0x2));

        uint256[] memory clearingPrices = new uint256[](2);
        clearingPrices[0] = 100;
        clearingPrices[1] = 200;

        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](1);
        trades[0] = GPv2Trade.Data({
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

        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        // Build the chained wrapper data:
        // solver -> wrapper1 -> wrapper2 -> wrapper3 -> static SETTLEMENT

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](3);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper1),
            data: hex""
        });
        wrapperCalls[1] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper2),
            data: hex""
        });
        wrapperCalls[2] = CowWrapperHelpers.WrapperCall({
            target: address(wrapper3),
            data: hex""
        });

        bytes memory wrapperData = helpers.verifyAndBuildWrapperData(wrapperCalls);
        bytes memory settleData = abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);

        // Call wrapper1 as the solver
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);

        // Verify that mockSettlement was called
        assertEq(mockSettlement.getSettleCallCount(), 1, "MockSettlement should be called once");

        // Verify the settlement received the correct parameters
        (uint256 tokenCount, uint256 priceCount, uint256 tradeCount,) = mockSettlement.getLastSettleCall();
        assertEq(tokenCount, 2, "Should have 2 tokens");
        assertEq(priceCount, 2, "Should have 2 prices");
        assertEq(tradeCount, 1, "Should have 1 trade");
    }
}
