// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapper, CowSettlement, CowAuthentication} from "../src/vendor/CowWrapper.sol";
import {IERC20, GPv2Trade, GPv2Interaction} from "cow/GPv2Settlement.sol";
import {EmptyWrapper} from "./EmptyWrapper.sol";

import {CowWrapperHelpers} from "../src/vendor/CowWrapperHelpers.sol";

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
        GPv2Interaction.Data[][3] interactions;
        bytes additionalData;
    }

    SettleCall[] public settleCalls;

    function settle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external {
        SettleCall storage call_ = settleCalls.push();
        call_.tokens = tokens;
        call_.clearingPrices = clearingPrices;
        for (uint256 i = 0;i < 3;i++) {
            for (uint256 j = 0;j < interactions[i].length;i++) {
                call_.interactions[i].push(interactions[i][j]);
            }
        }

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

contract CowWrapperTest is Test, CowWrapper {
    MockAuthentication public authenticator;
    MockSettlement public mockSettlement;
    CowWrapperHelpers helpers;
    address public solver;

    EmptyWrapper private wrapper1;
    EmptyWrapper private wrapper2;
    EmptyWrapper private wrapper3;

    // Track _wrap calls
    struct WrapCall {
        bytes settleData;
        bytes wrapperData;
    }

    WrapCall[] public wrapCalls;

    uint256 private skipWrappedData;

    constructor() CowWrapper(CowAuthentication(address(0))) {
        // Constructor will be called in setUp with proper authenticator
    }

    function setUp() public {
        // Deploy MockAuthentication and etch it to address(0) so the immutable AUTHENTICATOR works
        authenticator = new MockAuthentication();
        vm.etch(address(0), address(authenticator).code);

        solver = makeAddr("solver");
        // Add solver via address(0) which now has the MockAuthentication code
        MockAuthentication(address(0)).addSolver(solver);

        mockSettlement = new MockSettlement();
        helpers = new CowWrapperHelpers(CowAuthentication(address(0)), CowAuthentication(address(0)));

        // Create three EmptyWrapper instances
        wrapper1 = new EmptyWrapper(CowAuthentication(address(0)));
        wrapper2 = new EmptyWrapper(CowAuthentication(address(0)));
        wrapper3 = new EmptyWrapper(CowAuthentication(address(0)));

        // Add all wrappers as solvers
        MockAuthentication(address(0)).addSolver(address(wrapper1));
        MockAuthentication(address(0)).addSolver(address(wrapper2));
        MockAuthentication(address(0)).addSolver(address(wrapper3));

        // Add test contract as solver for test_wrap_ReceivesCorrectParameters
        MockAuthentication(address(0)).addSolver(address(this));
    }

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

    function parseWrapperData(bytes calldata wrapperData) external view override returns (bytes calldata remainingWrapperData) {
        // CowWrapperTest consumes skipWrappedData bytes
        return wrapperData[skipWrappedData:];
    }

    function test_wrap_ReceivesCorrectParameters() public {
        MockSettlement.SettleCall memory settlement;

        settlement.tokens = new IERC20[](1);
        settlement.tokens[0] = IERC20(address(0x1));

        settlement.clearingPrices = new uint256[](1);
        settlement.clearingPrices[0] = 100;

        settlement.trades = new GPv2Trade.Data[](0);
        settlement.interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory customWrapperData = hex"deadbeef";

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](1);
        wrapperCalls[0] = CowWrapperHelpers.WrapperCall({
            target: address(this),
            data: customWrapperData
        });

        skipWrappedData = customWrapperData.length;

        bytes memory settleData = abi.encodeCall(MockSettlement.settle, (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions));
        bytes memory wrapperData = helpers.verifyAndBuildWrapperData(wrapperCalls, address(mockSettlement));

        vm.prank(solver);
        this.wrappedSettle(settleData, wrapperData);
        skipWrappedData = 0;

        assertEq(wrapCalls.length, 1);
        assertGt(wrapCalls[0].settleData.length, 0);
        assertEq(wrapCalls[0].wrapperData, customWrapperData);
    }

    function test_internalSettle_CallsNextSettlement() public {
        MockSettlement.SettleCall memory settlement;

        settlement.tokens = new IERC20[](1);
        settlement.tokens[0] = IERC20(address(0x1));

        settlement.clearingPrices = new uint256[](1);
        settlement.clearingPrices[0] = 100;

        settlement.trades = new GPv2Trade.Data[](0);
        settlement.interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        CowWrapperHelpers.WrapperCall[] memory wrapperCalls = new CowWrapperHelpers.WrapperCall[](0);

        bytes memory settleData = abi.encodeCall(MockSettlement.settle, (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions));
        bytes memory wrapperData = helpers.verifyAndBuildWrapperData(wrapperCalls, address(mockSettlement));

        vm.prank(solver);
        this.wrappedSettle(settleData, wrapperData);

        assertEq(mockSettlement.getSettleCallCount(), 1);
        (uint256 tokenCount, uint256 priceCount, uint256 tradeCount,) = mockSettlement.getLastSettleCall();
        assertEq(tokenCount, 1);
        assertEq(priceCount, 1);
        assertEq(tradeCount, 0);
    }

    function test_wrappedSettle_RevertsWithWrapperHasNoSettleTarget() public {
        IERC20[] memory tokens = new IERC20[](0);
        uint256[] memory clearingPrices = new uint256[](0);
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory settleData =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        bytes memory wrapperData = hex""; // Empty wrapper data (less than 20 bytes)

        // Should revert when called without sufficient wrapper data
        vm.prank(solver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.WrapperHasNoSettleTarget.selector, 0, 20));
        this.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWithNotASolver() public {
        IERC20[] memory tokens = new IERC20[](0);
        uint256[] memory clearingPrices = new uint256[](0);
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory settleData =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        bytes memory wrapperData = abi.encodePacked(address(mockSettlement)); // Packed encoding of settlement address

        address notASolver = makeAddr("notASolver");

        // Should revert when called by non-solver
        vm.prank(notASolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, notASolver));
        this.wrappedSettle(settleData, wrapperData);
    }

    function test_integration_ThreeWrappersChained() public {
        MockSettlement.SettleCall memory settlement;

        settlement.tokens = new IERC20[](2);
        settlement.tokens[0] = IERC20(address(0x1));
        settlement.tokens[1] = IERC20(address(0x2));

        settlement.clearingPrices = new uint256[](2);
        settlement.clearingPrices[0] = 100;
        settlement.clearingPrices[1] = 200;

        settlement.trades = new GPv2Trade.Data[](1);
        settlement.trades[0] = GPv2Trade.Data({
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

        settlement.interactions = 
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        // Build the chained wrapper data:
        // solver -> wrapper1 -> wrapper2 -> wrapper3 -> mockSettlement

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

        bytes memory settleData = abi.encodeCall(MockSettlement.settle, (settlement.tokens, settlement.clearingPrices, settlement.trades, settlement.interactions));

        bytes memory wrapperData =
            helpers.verifyAndBuildWrapperData(wrapperCalls, address(mockSettlement));

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
