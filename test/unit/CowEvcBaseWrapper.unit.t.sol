// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {EIP712} from "openzeppelin/utils/cryptography/EIP712.sol";

import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";

import {CowEvcBaseWrapper, ICowSettlement, CowWrapper, IEVC} from "../../src/CowEvcBaseWrapper.sol";
import {PreApprovedHashes} from "../../src/PreApprovedHashes.sol";

contract MockEvcBaseWrapper is CowEvcBaseWrapper, EIP712 {
    struct TestParams {
        address owner;
        address account;
        uint256 number;
    }

    bool public needsPermission;

    constructor(address evc, address cow)
        CowEvcBaseWrapper(evc, ICowSettlement(cow), keccak256("CowEvcBaseWrapperTest"), keccak256("1"))
        EIP712("CowEvcBaseWrapperTest", "1")
    {
        PARAMS_SIZE = abi.encode(TestParams({owner: address(0), account: address(0), number: 0})).length;
        MAX_BATCH_OPERATIONS = 2;
        PARAMS_TYPE_HASH = keccak256("TestParams(address owner,address account,uint256 number)");

        // by default set needs permission so we dont get unused permission error
        needsPermission = true;
    }

    function _encodeBatchItemsBefore(ParamsLocation)
        internal
        view
        virtual
        override
        returns (IEVC.BatchItem[] memory items, bool _needsPermission)
    {
        // prevent unused variable warning
        return (new IEVC.BatchItem[](0), needsPermission);
    }

    function _evcInternalSettle(bytes calldata settleData, bytes calldata, bytes calldata remainingWrapperData)
        internal
        override
    {
        // We dont have anything special to do here, just call the next in chain
        _next(settleData, remainingWrapperData);
    }

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

    function setNeedsPermission(bool flag) external {
        needsPermission = flag;
    }
}

contract CowEvcBaseWrapperTest is Test {
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);

    bytes constant MOCK_SETTLEMENT_CALL = abi.encodeCall(
        ICowSettlement.settle,
        (
            new address[](0),
            new uint256[](0),
            new ICowSettlement.Trade[](0),
            [
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0)
            ]
        )
    );

    MockEvcBaseWrapper wrapper;

    function setUp() external {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEvc = new MockEVC();

        wrapper = new MockEvcBaseWrapper(address(mockEvc), address(mockSettlement));
    }

    function test_Constructor() public {
        // Test that constructor validates EVC address has code
        vm.expectRevert("EVC address is invalid");
        new MockEvcBaseWrapper(address(0x1234), address(mockSettlement));

        // Test that constructor sets EVC variable correctly
        assertEq(address(wrapper.EVC()), address(mockEvc), "EVC variable not set correctly");

        // Test that NONCE_NAMESPACE is set to the wrapper's address cast to uint256
        uint256 expectedNonceNamespace = uint256(uint160(address(wrapper)));
        assertEq(wrapper.NONCE_NAMESPACE(), expectedNonceNamespace, "NONCE_NAMESPACE not set correctly");

        // Test that DOMAIN_SEPARATOR is computed correctly according to EIP-712
        bytes32 domainTypeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                domainTypeHash, keccak256("CowEvcBaseWrapperTest"), keccak256("1"), block.chainid, address(wrapper)
            )
        );
        assertEq(wrapper.DOMAIN_SEPARATOR(), expectedDomainSeparator, "DOMAIN_SEPARATOR not computed correctly");
    }

    function test_UnusedPermitSignature() public {
        // Test that providing a signature when no permission is needed reverts
        wrapper.setNeedsPermission(false);

        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});

        vm.expectRevert(CowEvcBaseWrapper.UnusedPermitSignature.selector);
        wrapper.invokeEvc("", abi.encode(params, signature), new bytes(0), params, signature);
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
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_CallsOwnerWhenOwnerBitSet() public {
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        mockEvc.setOperatorMask(1);
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (OWNER, address(wrapper), false)));
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_CallsSubaccountWhenSubaccountBitSet() public {
        uint256 bitPosition = uint160(OWNER) ^ uint160(ACCOUNT);
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        /// forge-lint: disable-next-line(incorrect-shift)
        mockEvc.setOperatorMask(1 << bitPosition);
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (ACCOUNT, address(wrapper), false)));
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_CallsBothWhenBothBitsSet() public {
        uint256 bitPosition = uint160(OWNER) ^ uint160(ACCOUNT);
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        /// forge-lint: disable-next-line(incorrect-shift)
        mockEvc.setOperatorMask(1 | (1 << bitPosition));
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (ACCOUNT, address(wrapper), false)));
        vm.expectCall(address(mockEvc), abi.encodeCall(IEVC.setAccountOperator, (OWNER, address(wrapper), false)));
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_SetAccountOperator_NotCalledWithSignature() public {
        uint256 bitPosition = uint160(OWNER) ^ uint160(ACCOUNT);
        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});

        /// forge-lint: disable-next-line(incorrect-shift)
        mockEvc.setOperatorMask(1 | (1 << bitPosition));
        vm.expectCall(address(mockEvc), abi.encodePacked(IEVC.setAccountOperator.selector), 0);
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, signature), new bytes(0), params, signature);
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
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_EvcInternalSettle_OnlyEVC() public {
        bytes memory settleData = "";
        bytes memory remainingWrapperData = "";

        vm.expectRevert(abi.encodeWithSelector(CowEvcBaseWrapper.Unauthorized.selector, address(this)));
        wrapper.evcInternalSettle(settleData, hex"", remainingWrapperData);
    }

    function test_InvokeEvc_RevertsWhenEvcBatchFails() public {
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        // Configure EVC to fail on batch call

        vm.expectRevert("MockEVC: batch failed");
        vm.mockCallRevert(address(mockEvc), abi.encodeWithSelector(IEVC.batch.selector), "MockEVC: batch failed");
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_InvokeEvc_CallsSettlement() public {
        MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        // Ensure that the settlement is called
        vm.expectCall(address(mockSettlement), 0, MOCK_SETTLEMENT_CALL);
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }

    function test_InvokeEvc_FailsOnConsumedHash() public {
                MockEvcBaseWrapper.TestParams memory params =
            MockEvcBaseWrapper.TestParams({owner: OWNER, account: ACCOUNT, number: block.timestamp + 100});
        bytes32 approvalHash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(approvalHash, true);

        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));

        // Try to invoke the same wrapper data again - should fail because hash is consumed
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.AlreadyConsumed.selector, OWNER, approvalHash));
        wrapper.invokeEvc(MOCK_SETTLEMENT_CALL, abi.encode(params, new bytes(0)), new bytes(0), params, new bytes(0));
    }
}
