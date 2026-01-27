// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {EIP712} from "openzeppelin/utils/cryptography/EIP712.sol";

import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";

import {CowEvcBaseWrapper, ICowSettlement, CowWrapper, IEVC} from "../../src/CowEvcBaseWrapper.sol";

contract MockEvcBaseWrapper is CowEvcBaseWrapper, EIP712 {
    struct TestParams {
        address owner;
        address account;
        uint256 number;
    }

    constructor(address evc, address cow)
        CowEvcBaseWrapper(evc, ICowSettlement(cow), keccak256("CowEvcBaseWrapperTest"), keccak256("1"))
        EIP712("CowEvcBaseWrapperTest", "1")
    {
        PARAMS_SIZE = abi.encode(TestParams({owner: address(0), account: address(0), number: 0})).length;
        MAX_BATCH_OPERATIONS = 1;
        PARAMS_TYPE_HASH = keccak256("TestParams(address owner,address account,uint256 number)");
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

    function name() external pure override returns (string memory) {
        return "Test";
    }

    function validateWrapperData(bytes calldata wrapperData) external view override {}

    function getApprovalHash(TestParams memory params) external view returns (bytes32) {
        return _getApprovalHash(memoryLocation(params));
    }

    function getExpectedEip712Hash(TestParams memory params) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(PARAMS_TYPE_HASH, params.owner, params.account, params.number));
        return _hashTypedDataV4(structHash);
    }

    function invokeEvc(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData,
        TestParams memory params,
        bytes memory signature
    ) public {
        _invokeEvc(
            _makeInternalSettleCallbackData(settleData, wrapperData, remainingWrapperData),
            memoryLocation(params),
            signature,
            params.owner,
            params.account,
            params.number // using number as deadline for testing
        );
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

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);

    MockEvcBaseWrapper wrapper;

    function setUp() external {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEvc = new MockEVC();

        wrapper = new MockEvcBaseWrapper(address(mockEvc), address(mockSettlement));
    }

    function test_EIP712Compliance() public view {
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: address(0x123), account: address(0x123), number: 0x456});

        // Compute using OpenZeppelin's EIP712
        bytes32 expectedDigest = wrapper.getExpectedEip712Hash(params);

        // Compute using the base wrapper implementation
        bytes32 actualDigest = wrapper.getApprovalHash(params);

        assertEq(actualDigest, expectedDigest, "EIP712 digest mismatch");
    }

    // edge case: in the extremely unlikely case that the `wrappedSettle` function somehow is able to be
    // parsed/recognized without reverting on, we do this test just to ensure
    // callback cannot be the EVC.
    function test_EVC_CannotBeCalledWithWrappedSettle() public pure {
        // batch is the only function that is able to execute operatoins on behalf of the caller contract without reverting https://evc.wtf/docs/contracts/technical-reference/contract.EthereumVaultConnector#batch
        require(
            CowWrapper.wrappedSettle.selector != IEVC.batch.selector,
            "EVC.batch and ICowWrapper.wrappedSettle match selectors"
        );
        require(
            CowWrapper.wrappedSettle.selector != IEVC.call.selector,
            "EVC.call and ICowWrapper.wrappedSettle match selectors"
        );
    }

    function test_WrappedSettle_SubaccountMustBeControlledByOwner() public {
        address invalidSubaccount = 0x9999999999999999999999999999999999999999; // subaccount is not controlled by owner
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: invalidSubaccount, number: 0});
        bytes memory wrapperData = abi.encode(params, new bytes(0));

        bytes memory settleData = "";

        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcBaseWrapper.SubaccountMustBeControlledByOwner.selector, invalidSubaccount, OWNER
            )
        );
        wrapper.invokeEvc(settleData, wrapperData, new bytes(0), params, new bytes(0));
    }

    // NOTE: We have to use a bunch of separate tests here because `vm.expectCall` works across
    // the entire test, and we need to check many different conditions.
    function test_SetAccountOperator_NoCallsWhenMaskIsZero() public {
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        mockEvc.setOperatorMask(0);
        vm.expectCall(address(mockEvc), abi.encodePacked(IEVC.setAccountOperator.selector), 0);
        wrapper.invokeEvc("", abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_CallsOwnerWhenOwnerBitSet() public {
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        mockEvc.setOperatorMask(1);
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (OWNER, address(wrapper), false)));
        wrapper.invokeEvc("", abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_CallsSubaccountWhenSubaccountBitSet() public {
        uint256 bitPosition = uint160(OWNER) ^ uint160(ACCOUNT);
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        mockEvc.setOperatorMask(1 << bitPosition);
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (ACCOUNT, address(wrapper), false)));
        wrapper.invokeEvc("", abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_CallsBothWhenBothBitsSet() public {
        uint256 bitPosition = uint160(OWNER) ^ uint160(ACCOUNT);
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        mockEvc.setOperatorMask(1 | (1 << bitPosition));
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (ACCOUNT, address(wrapper), false)));
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (OWNER, address(wrapper), false)));
        wrapper.invokeEvc("", abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_NotCalledWithSignature() public {
        uint256 bitPosition = uint160(OWNER) ^ uint160(ACCOUNT);
        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});

        mockEvc.setOperatorMask(1 | (1 << bitPosition));
        vm.expectCall(address(mockEvc), abi.encodePacked(IEVC.setAccountOperator.selector), 0);
        wrapper.invokeEvc("", abi.encode(params, signature), new bytes(0), params, signature);
    }

    function test_SetAccountOperator_SkipsOwnerCallWhenOwnerEqualsAccount() public {
        address sameAddress = address(0x2222);
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: sameAddress, account: sameAddress, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);

        vm.prank(sameAddress);
        wrapper.setPreApprovedHash(approvalHash, true);

        // When owner == account, the owner bit check resolves to the subaccount bit check
        // So with mask = 1, one call is made (for the subaccount which is also the owner)
        // The separate owner call is skipped due to "owner != account" check
        mockEvc.setOperatorMask(1);
        vm.expectCall(
            address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (sameAddress, address(wrapper), false)), 1
        );
        wrapper.invokeEvc("", abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }
}
