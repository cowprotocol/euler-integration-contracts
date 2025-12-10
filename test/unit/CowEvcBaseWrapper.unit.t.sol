// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {EIP712} from "openzeppelin/utils/cryptography/EIP712.sol";

import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";

import "../../src/CowEvcBaseWrapper.sol";

contract MockEvcBaseWrapper is CowEvcBaseWrapper, EIP712 {
    bytes32 public constant TEST_PARAMS_TYPE_HASH = keccak256("TestParams(address owner,uint256 number)");

    struct TestParams {
        address owner;
        uint256 number;
    }

    constructor(address evc, address cow)
        CowEvcBaseWrapper(evc, ICowSettlement(cow), keccak256("CowEvcBaseWrapperTest"), keccak256("1"))
        EIP712("CowEvcBaseWrapperTest", "1")
    {
        PARAMS_SIZE = abi.encode(TestParams({owner: address(0), number: 0})).length;
        MAX_BATCH_OPERATIONS = 1;
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) internal override {}

    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {}

    function name() external view override returns (string memory) {
        return "Test";
    }

    function validateWrapperData(bytes calldata wrapperData) external view override {}

    function getApprovalHash(TestParams memory params) external view returns (bytes32) {
        return _getApprovalHash(TEST_PARAMS_TYPE_HASH, memoryLocation(params));
    }

    function getExpectedEIP712Hash(TestParams memory params) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(TEST_PARAMS_TYPE_HASH, params.owner, params.number));
        return _hashTypedDataV4(structHash);
    }

    function memoryLocation(TestParams memory params) public pure returns (ParamsLocation location) {
        assembly ("memory-safe") {
            location := params
        }
    }
}

contract CowEvcBaseWrapperTest is Test {
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;

    MockEvcBaseWrapper wrapper;

    function setUp() external {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEvc = new MockEVC();

        wrapper = new MockEvcBaseWrapper(address(mockEvc), address(mockSettlement));
    }

    function test_EIP712Compliance() public view {
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: address(0x123), number: 0x456});

        // Compute using OpenZeppelin's EIP712
        bytes32 expectedDigest = wrapper.getExpectedEIP712Hash(params);

        // Compute using the base wrapper implementation
        bytes32 actualDigest = wrapper.getApprovalHash(params);

        assertEq(actualDigest, expectedDigest, "EIP712 digest mismatch");
    }
}
