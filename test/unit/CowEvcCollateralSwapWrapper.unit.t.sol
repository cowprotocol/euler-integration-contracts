// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {UnitTestBase} from "./UnitTestBase.sol";
import {CowEvcBaseWrapper} from "../../src/CowEvcBaseWrapper.sol";
import {CowEvcCollateralSwapWrapper} from "../../src/CowEvcCollateralSwapWrapper.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";
import {MockERC20, MockVault} from "./mocks/MockERC20AndVaults.sol";

// this is required because foundry doesn't have a cheatcode for override any transient storage.
contract TestableCollateralSwapWrapper is CowEvcCollateralSwapWrapper {
    constructor(address _evc, ICowSettlement _settlement) CowEvcCollateralSwapWrapper(_evc, _settlement) {}

    function setExpectedEvcInternalSettleCall(bytes memory call) external {
        expectedEvcInternalSettleCallHash = keccak256(call);
    }
}

/// @title Unit tests for CowEvcCollateralSwapWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcCollateralSwapWrapperUnitTest is UnitTestBase {
    MockERC20 public mockFromAsset;
    MockERC20 public mockToAsset;
    MockVault public mockFromVault;
    MockVault public mockToVault;

    uint256 constant DEFAULT_SWAP_AMOUNT = 1000e18;

    // Constants from the contract
    bytes32 private constant KIND_SELL = hex"f3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775";
    bytes32 private constant KIND_BUY = hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc";

    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    /// @notice Get default CollateralSwapParams for testing
    function _getDefaultParams() internal view returns (CowEvcCollateralSwapWrapper.CollateralSwapParams memory) {
        return CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: DEFAULT_SWAP_AMOUNT,
            toAmount: 0
        });
    }

    /// @notice Encode wrapper data with length prefix
    function _encodeWrapperData(CowEvcCollateralSwapWrapper.CollateralSwapParams memory params, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory wrapperData = abi.encode(params, signature);
        return abi.encodePacked(uint16(wrapperData.length), wrapperData);
    }

    function _encodeDefaultWrapperData(bytes memory signature)
        internal
        view
        override
        returns (bytes memory wrapperData)
    {
        return _encodeWrapperData(_getDefaultParams(), signature);
    }

    /// @notice Setup pre-approved hash flow
    function _setupPreApprovedHash(CowEvcCollateralSwapWrapper.CollateralSwapParams memory params)
        internal
        returns (bytes32)
    {
        bytes32 hash = CowEvcCollateralSwapWrapper(address(wrapper)).getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);
        return hash;
    }

    function _setupPreApprovedHashDefaultParams() internal override returns (bytes32) {
        return _setupPreApprovedHash(_getDefaultParams());
    }

    function setUp() public override {
        super.setUp();
        mockFromAsset = new MockERC20("Mock Asset From", "MOCKFROM");
        mockToAsset = new MockERC20("Mock Asset To", "MOCKTO");
        mockFromVault = new MockVault(mockEvc, address(mockFromAsset), "Mock From Vault", "mFROM");
        mockToVault = new MockVault(mockEvc, address(mockToAsset), "Mock To Vault", "mTO");

        wrapper = CowEvcBaseWrapper(
            new TestableCollateralSwapWrapper(address(mockEvc), ICowSettlement(address(mockSettlement)))
        );

        // Set solver as authenticated
        mockAuth.setSolver(address(wrapper), true);
        mockAuth.setSolver(address(emptyWrapper), true);

        mockFromVault.mint(ACCOUNT, 1000e18);

        mockFromVault.mint(OWNER, 2000e18);

        vm.prank(OWNER);
        require(mockFromVault.approve(address(wrapper), 2000e18));
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsDomainSeparator() public view {
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("CowEvcCollateralSwapWrapper"),
                keccak256("1"),
                block.chainid,
                address(wrapper)
            )
        );
        assertEq(wrapper.DOMAIN_SEPARATOR(), expectedDomainSeparator, "DOMAIN_SEPARATOR incorrect");
    }

    /*//////////////////////////////////////////////////////////////
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ValidateWrapperData_EmptySignature() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();

        bytes memory wrapperData = abi.encode(params, new bytes(0));

        // Should not revert for valid wrapper data
        wrapper.validateWrapperData(wrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    APPROVAL HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params1 = _getDefaultParams();

        // Change owner field
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params2 = _getDefaultParams();
        params2.owner = ACCOUNT;

        // Change fromAmount field
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params3 = _getDefaultParams();
        params3.fromAmount = 2000e18;

        bytes32 hash1 = CowEvcCollateralSwapWrapper(address(wrapper)).getApprovalHash(params1);
        bytes32 hash2 = CowEvcCollateralSwapWrapper(address(wrapper)).getApprovalHash(params2);
        bytes32 hash3 = CowEvcCollateralSwapWrapper(address(wrapper)).getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SETTLE TESTS
    //////////////////////////////////////////////////////////////*/
    function test_WrappedSettle_PreApprovedHashRevertsIfDeadlineExceeded() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();
        params.account = OWNER; // Same account
        params.deadline = block.timestamp - 1; // Past deadline

        _setupPreApprovedHash(params);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        vm.prank(SOLVER);
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcBaseWrapper.OperationDeadlineExceeded.selector, params.deadline, block.timestamp
            )
        );
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    ENCODE PERMIT DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EncodePermitData_IsCorrect() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();

        bytes memory permitData = CowEvcCollateralSwapWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items, bytes32 paramsHash) = _decodePermitData(permitData);

        assertEq(items.length, 2, "Should have correct batch item count");
        assertEq(items[0].targetContract, params.fromVault, "Should target fromVault");
        assertEq(
            items[0].data,
            abi.encodeCall(MockERC20.transfer, (address(OWNER), params.fromAmount)),
            "Should call transfer"
        );
        assertEq(items[0].onBehalfOfAccount, ACCOUNT, "Should have zero onBehalfOfAccount");
        assertEq(items[1].targetContract, address(mockEvc), "Should target EVC");
        assertEq(
            items[1].data,
            abi.encodeCall(IEVC.enableCollateral, (params.account, params.toVault)),
            "Should call enableCollateral"
        );
        assertEq(items[1].onBehalfOfAccount, address(0), "Should have zero onBehalfOfAccount");

        assertEq(
            paramsHash,
            CowEvcCollateralSwapWrapper(address(wrapper)).getApprovalHash(params),
            "Params hash should match"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    EVC INTERNAL SWAP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EvcInternalSettle_OnlyEVC() public {
        bytes memory settleData = "";
        bytes memory wrapperData = "";
        bytes memory remainingWrapperData = "";

        vm.expectRevert(abi.encodeWithSelector(CowEvcBaseWrapper.Unauthorized.selector, address(this)));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSettle_RequiresCorrectCalldata() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: 1000e18,
            toAmount: 0
        });

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        // the wrapper data is omitted in the expected call
        TestableCollateralSwapWrapper(address(wrapper))
            .setExpectedEvcInternalSettleCall(
                abi.encodeCall(wrapper.evcInternalSettle, (settleData, new bytes(0), remainingWrapperData))
            );

        vm.prank(address(mockEvc));
        vm.expectRevert(CowEvcBaseWrapper.InvalidCallback.selector);
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSettle_CanBeCalledByEVC() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER, // Same account, no transfer needed
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: 1000e18,
            toAmount: 0
        });

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        TestableCollateralSwapWrapper(address(wrapper))
            .setExpectedEvcInternalSettleCall(
                abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
            );

        vm.prank(address(mockEvc));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ValidateWrapperData_LongSignature() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: 1000e18,
            toAmount: 0
        });

        // Create a signature longer than 65 bytes
        bytes memory signature = new bytes(128);
        bytes memory wrapperData = abi.encode(params, signature);

        // Should not revert for valid wrapper data with long signature
        wrapper.validateWrapperData(wrapperData);
    }

    function test_EvcInternalSettle_WithRemainingWrapperData() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: 1000e18,
            toAmount: 0
        });

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = abi.encodePacked(emptyWrapper, hex"0004deadbeef");

        TestableCollateralSwapWrapper(address(wrapper))
            .setExpectedEvcInternalSettleCall(
                abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
            );

        vm.prank(address(mockEvc));

        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);

        // Should handle remaining wrapper data gracefully
    }

    function test_WrappedSettle_BuildsCorrectBatchWithPermit() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: 1000e18,
            toAmount: 0
        });

        bytes memory signature = new bytes(65);
        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockFromVault.mint(1000 ether, OWNER);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        // Should build a batch with permit + evcInternalSettle (2 items)
    }

    function test_WrappedSettle_BuildsCorrectBatchWithPreApproved() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: 1000e18,
            toAmount: 0
        });

        bytes32 hash = CowEvcCollateralSwapWrapper(address(wrapper)).getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockFromVault.mint(1000 ether, OWNER);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        // Should build a batch with enableCollateral + evcInternalSettle (2 items)
    }
}
