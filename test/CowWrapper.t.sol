// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapper, CowSettlement} from "../src/vendor/CowWrapper.sol";
import {IERC20, GPv2Trade, GPv2Interaction, GPv2Authentication} from "cow/GPv2Settlement.sol";
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

contract MockSettlement is CowSettlement {
    struct SettleCall {
        IERC20[] tokens;
        uint256[] clearingPrices;
        GPv2Trade.Data[] trades;
        bytes additionalData;
    }

    SettleCall[] public settleCalls;

    function settle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata
    ) external override {
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

contract CowWrapperTest is Test, CowWrapper {
    MockAuthentication public authenticator;
    MockSettlement public mockSettlement;
    address public solver;

    EmptyWrapper private wrapper1;
    EmptyWrapper private wrapper2;
    EmptyWrapper private wrapper3;

    // Track _wrap calls
    struct WrapCall {
        IERC20[] tokens;
        uint256[] clearingPrices;
        GPv2Trade.Data[] trades;
        bytes wrapperData;
    }

    WrapCall[] public wrapCalls;

    uint256 private skipWrappedData;

    constructor() CowWrapper(GPv2Authentication(address(0))) {
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

        // Create three EmptyWrapper instances
        wrapper1 = new EmptyWrapper(GPv2Authentication(address(0)));
        wrapper2 = new EmptyWrapper(GPv2Authentication(address(0)));
        wrapper3 = new EmptyWrapper(GPv2Authentication(address(0)));

        // Add all wrappers as solvers
        MockAuthentication(address(0)).addSolver(address(wrapper1));
        MockAuthentication(address(0)).addSolver(address(wrapper2));
        MockAuthentication(address(0)).addSolver(address(wrapper3));

    }

    function _wrap(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrapperData
    ) internal override {
        // Record the wrap call
        WrapCall storage call_ = wrapCalls.push();
        call_.tokens = tokens;
        call_.clearingPrices = clearingPrices;
        for (uint256 i = 0; i < trades.length; i++) {
            call_.trades.push(trades[i]);
        }
        call_.wrapperData = wrapperData[0:skipWrappedData];

        // Call internal settle
        _internalSettle(tokens, clearingPrices, trades, interactions, wrapperData[skipWrappedData:]);
    }

    // These function needs to be exposed because the internal function expects calldata, so this is convienience to accomplish that
    function exposed_settleCalldataLength(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions
    ) external pure returns (uint256, uint256) {
        return _settleCalldataLength(tokens, interactions);
    }

    function exposed_internalSettle(
        IERC20[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2Trade.Data[] calldata trades,
        GPv2Interaction.Data[][3] calldata interactions,
        bytes calldata wrapperData
    ) external {
        _internalSettle(tokens, clearingPrices, trades, interactions, wrapperData);
    }

    function test_debug_tradeEncoding() public view {
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
            appData: bytes32(0),
            feeAmount: 10,
            flags: 0,
            executedAmount: 0,
            signature: hex"1234567890"
        });

        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory encoded = abi.encodeWithSelector(this.settle.selector, tokens, clearingPrices, trades, interactions);

        // Log the length difference
        (, uint256 calculated) = this.exposed_settleCalldataLength(tokens, clearingPrices, trades, interactions);
        uint256 actual = encoded.length;

        // The difference tells us what we're missing
        // Actual (996) - Calculated (873) = 123 bytes
        assertEq(calculated, actual, "Length mismatch");
    }

    function test_settleCalldataLength_EmptyArrays() public view {
        IERC20[] memory tokens = new IERC20[](0);
        uint256[] memory clearingPrices = new uint256[](0);
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        (, uint256 length) = this.exposed_settleCalldataLength(tokens, clearingPrices, trades, interactions);

        assertEq(
            length, abi.encodeWithSelector(this.settle.selector, tokens, clearingPrices, trades, interactions).length
        );
    }

    function test_settleCalldataLength_WithTokensAndPrices() public view {
        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(address(0x1));
        tokens[1] = IERC20(address(0x2));

        uint256[] memory clearingPrices = new uint256[](2);
        clearingPrices[0] = 100;
        clearingPrices[1] = 200;

        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        (, uint256 length) = this.exposed_settleCalldataLength(tokens, clearingPrices, trades, interactions);

        assertEq(
            length, abi.encodeWithSelector(this.settle.selector, tokens, clearingPrices, trades, interactions).length
        );
    }

    function test_settleCalldataLength_WithOneTrade() public view {
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
            appData: bytes32(0),
            feeAmount: 10,
            flags: 0,
            executedAmount: 0,
            signature: hex"1234567890"
        });

        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        (, uint256 length) = this.exposed_settleCalldataLength(tokens, clearingPrices, trades, interactions);

        assertEq(
            length, abi.encodeWithSelector(this.settle.selector, tokens, clearingPrices, trades, interactions).length
        );
    }

    function test_settleCalldataLength_WithInteractions() public view {
        IERC20[] memory tokens = new IERC20[](0);
        uint256[] memory clearingPrices = new uint256[](0);
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);

        GPv2Interaction.Data[][3] memory interactions;
        interactions[0] = new GPv2Interaction.Data[](1);
        interactions[0][0] = GPv2Interaction.Data({target: address(0x456), value: 0, callData: hex"aabbccdd"});
        interactions[1] = new GPv2Interaction.Data[](0);
        interactions[2] = new GPv2Interaction.Data[](0);

        (, uint256 length) = this.exposed_settleCalldataLength(tokens, clearingPrices, trades, interactions);

        assertEq(
            length, abi.encodeWithSelector(this.settle.selector, tokens, clearingPrices, trades, interactions).length
        );
    }

    function test_settleCalldataLength_ComplexCase() public view {
        IERC20[] memory tokens = new IERC20[](3);
        tokens[0] = IERC20(address(0x1));
        tokens[1] = IERC20(address(0x2));
        tokens[2] = IERC20(address(0x3));

        uint256[] memory clearingPrices = new uint256[](3);
        clearingPrices[0] = 100;
        clearingPrices[1] = 200;
        clearingPrices[2] = 300;

        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](2);
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
        trades[1] = GPv2Trade.Data({
            sellTokenIndex: 1,
            buyTokenIndex: 2,
            receiver: address(0x456),
            sellAmount: 2000,
            buyAmount: 1800,
            validTo: uint32(block.timestamp + 2000),
            appData: bytes32(uint256(2)),
            feeAmount: 20,
            flags: 1,
            executedAmount: 0,
            signature: hex"112233445566778899aabbcc"
        });

        GPv2Interaction.Data[][3] memory interactions;
        interactions[0] = new GPv2Interaction.Data[](1);
        interactions[0][0] = GPv2Interaction.Data({target: address(0x789), value: 100, callData: hex"00112233"});
        interactions[1] = new GPv2Interaction.Data[](0);
        interactions[2] = new GPv2Interaction.Data[](1);
        interactions[2][0] = GPv2Interaction.Data({target: address(0xabc), value: 0, callData: hex"deadbeefcafe"});

        (, uint256 length) = this.exposed_settleCalldataLength(tokens, clearingPrices, trades, interactions);

        // Base: 452, Tokens: 96, Prices: 96, Trade1: 325, Trade2: 332, Int[0][0]: 132, Int[2][0]: 134
        assertEq(
            length, abi.encodeWithSelector(this.settle.selector, tokens, clearingPrices, trades, interactions).length
        );
    }

    function test_wrap_ReceivesCorrectParameters() public {
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(address(0x1));

        uint256[] memory clearingPrices = new uint256[](1);
        clearingPrices[0] = 100;

        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        bytes memory wrapperData = hex"deadbeef";

        address nextSettlement = address(mockSettlement);
        bytes memory additionalData = abi.encodePacked(wrapperData, abi.encode(nextSettlement));
        bytes memory settleCalldata =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        bytes memory fullCalldata = abi.encodePacked(settleCalldata, additionalData);

        skipWrappedData = wrapperData.length;

        vm.prank(solver);
        (bool success,) = address(this).call(fullCalldata);
        skipWrappedData = 0;
        assertTrue(success);

        assertEq(wrapCalls.length, 1);
        assertEq(wrapCalls[0].tokens.length, 1);
        assertEq(wrapCalls[0].clearingPrices.length, 1);
        assertEq(wrapCalls[0].wrapperData, wrapperData);
    }

    function test_internalSettle_CallsNextSettlement() public {
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(address(0x1));

        uint256[] memory clearingPrices = new uint256[](1);
        clearingPrices[0] = 100;

        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        address nextSettlement = address(mockSettlement);

        bytes memory settleCalldata =
            abi.encodeWithSelector(CowSettlement.settle.selector, tokens, clearingPrices, trades, interactions);
        bytes memory fullCalldata = abi.encodePacked(settleCalldata, abi.encode(nextSettlement));

        vm.prank(solver);
        (bool success,) = address(this).call(fullCalldata);
        assertTrue(success);

        assertEq(mockSettlement.getSettleCallCount(), 1);
        (uint256 tokenCount, uint256 priceCount, uint256 tradeCount,) = mockSettlement.getLastSettleCall();
        assertEq(tokenCount, 1);
        assertEq(priceCount, 1);
        assertEq(tradeCount, 0);
    }

    function test_settle_RevertsWithWrapperHasNoSettleTarget() public {
        IERC20[] memory tokens = new IERC20[](0);
        uint256[] memory clearingPrices = new uint256[](0);
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        // Should revert when called without any additional wrapper data
        vm.prank(solver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.WrapperHasNoSettleTarget.selector, 420, 420));
        this.settle(tokens, clearingPrices, trades, interactions);
    }

    function test_settle_RevertsWithNotASolver() public {
        IERC20[] memory tokens = new IERC20[](0);
        uint256[] memory clearingPrices = new uint256[](0);
        GPv2Trade.Data[] memory trades = new GPv2Trade.Data[](0);
        GPv2Interaction.Data[][3] memory interactions =
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)];

        address notASolver = makeAddr("notASolver");

        // Should revert when called by non-solver
        vm.prank(notASolver);
        vm.expectRevert(abi.encodeWithSelector(CowWrapper.NotASolver.selector, notASolver));
        this.settle(tokens, clearingPrices, trades, interactions);
    }

    function test_integration_ThreeWrappersChained() public {
        CowWrapperHelpers.SettleCall memory settlement;

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

        address[] memory wrappers = new address[](3);
        wrappers[0] = address(wrapper1);
        wrappers[1] = address(wrapper2);
        wrappers[2] = address(wrapper3);

        bytes[] memory wrapperDatas = new bytes[](3);

        (address target, bytes memory fullCalldata) = CowWrapperHelpers.encodeWrapperCall(wrappers, wrapperDatas, address(mockSettlement), settlement);

        // Call wrapper1 as the solver
        vm.prank(solver);
        (bool success,) = address(wrapper1).call(fullCalldata);
        assertTrue(success, "Chained wrapper call should succeed");

        // Verify that mockSettlement was called
        assertEq(mockSettlement.getSettleCallCount(), 1, "MockSettlement should be called once");

        // Verify the settlement received the correct parameters
        //(uint256 tokenCount, uint256 priceCount, uint256 tradeCount,) = mockSettlement.getLastSettleCall();
        //assertEq(tokenCount, 2, "Should have 2 tokens");
        //assertEq(priceCount, 2, "Should have 2 prices");
        //assertEq(tradeCount, 1, "Should have 1 trade");
    }
}
