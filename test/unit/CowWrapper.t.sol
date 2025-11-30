// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {CowWrapper, ICowWrapper, ICowSettlement, ICowAuthentication} from "../../src/CowWrapper.sol";
import {EmptyWrapper} from "../EmptyWrapper.sol";

import {MockWrapper, MockCowSettlement, MockCowAuthentication} from "./mocks/MockCowProtocol.sol";

import {CowWrapperHelpers} from "../helpers/CowWrapperHelpers.sol";

contract CowWrapperTest is Test {
    MockCowAuthentication public authenticator;
    MockCowSettlement public mockSettlement;
    address public solver;

    MockWrapper private wrapper1;
    MockWrapper private wrapper2;
    MockWrapper private wrapper3;

    function setUp() public {
        // Deploy mock contracts
        authenticator = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(authenticator));

        solver = makeAddr("solver");
        // Add solver to the authenticator
        authenticator.setSolver(solver, true);

        // Create test wrapper and three EmptyWrapper instances with the settlement contract
        // (use type(uint16).max because it will force consuming all the wrapper data, which is
        // most useful for these tests)
        wrapper1 = new MockWrapper(ICowSettlement(address(mockSettlement)), type(uint16).max);
        wrapper2 = new MockWrapper(ICowSettlement(address(mockSettlement)), type(uint16).max);
        wrapper3 = new MockWrapper(ICowSettlement(address(mockSettlement)), type(uint16).max);

        // Add all wrappers as solvers
        authenticator.setSolver(address(wrapper1), true);
        authenticator.setSolver(address(wrapper2), true);
        authenticator.setSolver(address(wrapper3), true);
    }

    function _emptyInteractions() private pure returns (ICowSettlement.Interaction[][3] memory) {
        return
            [
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0)
            ];
    }

    function _createSimpleSettleData(uint256 tokenCount) private returns (bytes memory) {
        address[] memory tokens = new address[](tokenCount);
        uint256[] memory clearingPrices = new uint256[](tokenCount);
        for (uint256 i = 0; i < tokenCount; i++) {
            tokens[i] = makeAddr(string.concat("Settle Token #", vm.toString(i + 1)));
            clearingPrices[i] = 100 * (i + 1);
        }
        return abi.encodeCall(
            ICowSettlement.settle, (tokens, clearingPrices, new ICowSettlement.Trade[](0), _emptyInteractions())
        );
    }

    function test_verifyInitialState() public {
        assertEq(
            address(wrapper1.SETTLEMENT()),
            address(mockSettlement),
            "Settlement contract should be initialized correctly"
        );
        assertEq(
            address(wrapper1.AUTHENTICATOR()),
            address(authenticator),
            "Authenticator contract should be initialized from the settlement contract"
        );
    }

    function test_next_CallsWrapperAndThenNextSettlement() public {
        bytes memory settleData = abi.encodePacked(_createSimpleSettleData(1), hex"123456");
        // here we encode [2-byte len] followed by the actual wrapper data (which is 3 bytes, 6 chars hex)
        bytes memory secondCallWrapperData = abi.encodePacked(uint16(3), hex"098765");
        // here we encode [2-byte len] followed by the actual wrapper data (which is 2 bytes, 4 chars hex), and build the chain
        bytes memory wrapperData = abi.encodePacked(uint16(2), hex"1234", address(wrapper1), secondCallWrapperData);

        // verify the outside wrapper call data
        vm.expectCall(address(wrapper1), abi.encodeCall(ICowWrapper.wrappedSettle, (settleData, wrapperData)));

        // verify the internal wrapper call data
        vm.expectCall(address(wrapper1), abi.encodeCall(ICowWrapper.wrappedSettle, (settleData, secondCallWrapperData)));

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
        // Set up a more sophisticated settlement call to make sure it all gets through as expected.
        CowWrapperHelpers.SettleCall memory settlement;
        settlement.tokens = new address[](2);
        settlement.tokens[0] = address(0x1);
        settlement.tokens[1] = address(0x2);
        settlement.clearingPrices = new uint256[](2);
        settlement.clearingPrices[0] = 100;
        settlement.clearingPrices[1] = 200;

        settlement.trades = new ICowSettlement.Trade[](10);
        for (uint256 i = 0; i < 10; i++) {
            settlement.trades[i] = ICowSettlement.Trade({
                sellTokenIndex: 0,
                buyTokenIndex: 1,
                receiver: address(0x123),
                sellAmount: 1000 * i,
                buyAmount: 900 * i,
                validTo: uint32(block.timestamp + 1000),
                appData: bytes32(uint256(1)),
                feeAmount: 10,
                flags: 0,
                executedAmount: 0,
                signature: hex"aabbccddee"
            });
        }

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

        // all the wrappers get called, with wrapper 1 called twice

        // we only want to verify that wrappedSettle was called. (not the specific data passed to wrappedSettle)
        bytes memory wrappedSettleSelector = abi.encodePacked(ICowWrapper.wrappedSettle.selector);
        vm.expectCall(address(wrapper1), 0, wrappedSettleSelector, 2);
        vm.expectCall(address(wrapper2), 0, wrappedSettleSelector, 1);
        vm.expectCall(address(wrapper3), 0, wrappedSettleSelector, 1);

        // the settlement gets called with the full data
        vm.expectCall(address(mockSettlement), new bytes(0));

        // Call wrapper1 as the solver
        vm.prank(solver);
        (bool success,) = target.call(fullCalldata);
        assertTrue(success, "Chained wrapper call should succeed");
    }

    function test_wrappedSettle_RevertsOnZeroLengthWrapperData() public {
        bytes memory settleData = _createSimpleSettleData(0);
        bytes memory wrapperData = hex""; // Completely empty wrapper data

        vm.prank(solver);
        vm.expectRevert(); // Should revert with out-of-bounds array access
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsOnOneByteWrapperData() public {
        bytes memory settleData = _createSimpleSettleData(0);
        bytes memory wrapperData = hex"01"; // Only 1 byte - not enough to read the 2-byte length

        vm.prank(solver);
        vm.expectRevert(); // Should revert with out-of-bounds array access
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_SucceedsWithZeroLengthIndicator() public {
        bytes memory settleData = _createSimpleSettleData(0);
        bytes memory wrapperData = hex"0000"; // 2 bytes indicating 0-length wrapper data

        // Should call settlement directly with no wrapper-specific data
        vm.expectCall(address(mockSettlement), 0, settleData, 1);

        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_SucceedsWithMaximumLengthWrapperData() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Create maximum length wrapper data (65535 bytes)
        // Format: [2-byte length = 0xFFFF][65535 bytes of data]
        bytes memory maxData = new bytes(65535);
        for (uint256 i = 0; i < 65535; i++) {
            maxData[i] = bytes1(uint8(i % 256));
        }

        bytes memory wrapperData = abi.encodePacked(uint16(65535), maxData);

        // Should successfully parse the maximum length data and call settlement
        vm.expectCall(address(mockSettlement), 0, settleData, 1);

        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWhenDataShorterThanIndicated() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Wrapper data claims to be 100 bytes but only provides 50
        bytes memory shortData = new bytes(50);
        bytes memory wrapperData = abi.encodePacked(uint16(100), shortData);

        vm.prank(solver);
        vm.expectRevert(); // Should revert with out-of-bounds array access
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_SucceedsWithMaxLengthAndNextWrapper() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Create maximum length wrapper data followed by next wrapper address
        bytes memory maxData = new bytes(65535);
        for (uint256 i = 0; i < 65535; i++) {
            maxData[i] = bytes1(uint8(i % 256));
        }

        // Format: [2-byte length = 0xFFFF][65535 bytes of data][20-byte next wrapper address][remaining data]
        bytes memory nextWrapperData = hex"00030000FF"; // 3 bytes of data for next wrapper
        bytes memory wrapperData = abi.encodePacked(type(uint16).max, maxData, address(wrapper2), nextWrapperData);

        // Should call wrapper2 with the remaining data
        vm.expectCall(address(wrapper2), 0, abi.encodePacked(ICowWrapper.wrappedSettle.selector), 1);

        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWithInsufficientLengthData() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Format: [1-byte length = 1 (insufficient)]
        bytes memory wrapperData = hex"01";

        vm.expectRevert(new bytes(0));
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }

    function test_wrappedSettle_RevertsWithInsufficientCallData() public {
        bytes memory settleData = _createSimpleSettleData(0);

        // Format: [2-byte length = 0xa][9 bytes of data (insufficient)]
        bytes memory wrapperData = hex"000A123412341234123412";

        vm.expectRevert(new bytes(0));
        vm.prank(solver);
        wrapper1.wrappedSettle(settleData, wrapperData);
    }
}
