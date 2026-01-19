// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcBaseWrapper} from "../../src/CowEvcBaseWrapper.sol";
import {CowEvcCollateralSwapWrapper} from "../../src/CowEvcCollateralSwapWrapper.sol";
import {PreApprovedHashes} from "../../src/PreApprovedHashes.sol";
import {EmptyWrapper} from "../EmptyWrapper.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";
import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";
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
contract CowEvcCollateralSwapWrapperUnitTest is Test {
    TestableCollateralSwapWrapper public wrapper;
    EmptyWrapper public emptyWrapper;
    MockEVC public mockEvc;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;
    MockERC20 public mockFromAsset;
    MockERC20 public mockToAsset;
    MockVault public mockFromVault;
    MockVault public mockToVault;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address constant SOLVER = address(0x3333);

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

    /// @notice Create empty settle data
    function _getEmptySettleData() internal view returns (bytes memory) {
        address[] memory tokens = new address[](2);
        tokens[0] = address(mockFromVault);
        tokens[1] = address(mockToVault);
        uint256[] memory prices = new uint256[](2);
        prices[0] = 1 ether;
        prices[1] = 2 ether;
        return abi.encodeCall(
            ICowSettlement.settle,
            (
                tokens,
                prices,
                new ICowSettlement.Trade[](0),
                [
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0),
                    new ICowSettlement.Interaction[](0)
                ]
            )
        );
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

    /// @notice Setup pre-approved hash flow
    function _setupPreApprovedHash(CowEvcCollateralSwapWrapper.CollateralSwapParams memory params)
        internal
        returns (bytes32)
    {
        bytes32 hash = wrapper.getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);
        mockEvc.setOperator(OWNER, address(wrapper), true);
        return hash;
    }

    /// @notice Decode signed calldata helper
    function _decodeSignedCalldata(bytes memory signedCalldata) internal pure returns (IEVC.BatchItem[] memory) {
        bytes memory encodedItems = new bytes(signedCalldata.length - 4);
        for (uint256 i = 4; i < signedCalldata.length; i++) {
            encodedItems[i - 4] = signedCalldata[i];
        }
        return abi.decode(encodedItems, (IEVC.BatchItem[]));
    }

    function setUp() public {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEvc = new MockEVC();
        mockFromAsset = new MockERC20("Mock Asset From", "MOCKFROM");
        mockToAsset = new MockERC20("Mock Asset To", "MOCKTO");
        mockFromVault = new MockVault(mockEvc, address(mockFromAsset), "Mock From Vault", "mFROM");
        mockToVault = new MockVault(mockEvc, address(mockToAsset), "Mock To Vault", "mTO");

        wrapper = new TestableCollateralSwapWrapper(address(mockEvc), ICowSettlement(address(mockSettlement)));
        emptyWrapper = new EmptyWrapper(ICowSettlement(address(mockSettlement)));

        // Set solver as authenticated
        mockAuth.setSolver(SOLVER, true);
        mockAuth.setSolver(address(wrapper), true);
        mockAuth.setSolver(address(emptyWrapper), true);

        // Set the correct onBehalfOfAccount for evcInternalSettle calls
        mockEvc.setOnBehalfOf(ACCOUNT);

        vm.label(OWNER, "OWNER");
        vm.label(ACCOUNT, "ACCOUNT");
        vm.label(SOLVER, "SOLVER");
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(wrapper.EVC()), address(mockEvc), "EVC not set correctly");
        assertEq(address(wrapper.SETTLEMENT()), address(mockSettlement), "SETTLEMENT not set correctly");
        assertEq(address(wrapper.AUTHENTICATOR()), address(mockAuth), "AUTHENTICATOR not set correctly");
        assertEq(wrapper.NONCE_NAMESPACE(), uint256(uint160(address(wrapper))), "NONCE_NAMESPACE incorrect");
    }

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

        bytes32 hash1 = wrapper.getApprovalHash(params1);
        bytes32 hash2 = wrapper.getApprovalHash(params2);
        bytes32 hash3 = wrapper.getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    /*//////////////////////////////////////////////////////////////
                    GET SIGNED CALLDATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetSignedCalldata_IsCorrect() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();

        bytes memory signedCalldata = wrapper.encodePermitData(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

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

        mockSettlement.setSuccessfulSettle(true);

        // Set incorrect onBehalfOfAccount (not address(wrapper))
        mockEvc.setOnBehalfOf(address(0x9999));

        // the wrapper data is omitted in the expected call
        wrapper.setExpectedEvcInternalSettleCall(
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

        mockSettlement.setSuccessfulSettle(true);

        wrapper.setExpectedEvcInternalSettleCall(
            abi.encodeCall(wrapper.evcInternalSettle, (settleData, wrapperData, remainingWrapperData))
        );

        vm.prank(address(mockEvc));
        wrapper.evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WrappedSettle_OnlySolver() public {
        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        vm.expectRevert(abi.encodeWithSignature("NotASolver(address)", address(this)));
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_SubaccountMustBeControlledByOwner() public {
        address invalidSubaccount = 0x9999999999999999999999999999999999999999; // subaccount is not controlled by owner
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: invalidSubaccount,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            fromAmount: 1000e18,
            toAmount: 0
        });
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory chainedWrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        bytes memory settleData = "";

        vm.prank(SOLVER);
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcBaseWrapper.SubaccountMustBeControlledByOwner.selector, invalidSubaccount, OWNER
            )
        );
        wrapper.wrappedSettle(settleData, chainedWrapperData);
    }

    function test_WrappedSettle_WithPermitSignature() public {
        mockFromVault.mint(OWNER, 2000e18);

        vm.prank(OWNER);
        mockFromVault.approve(address(wrapper), 2000e18);

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();
        params.account = OWNER; // Same account

        bytes memory signature = new bytes(65);
        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, signature);

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        mockFromVault.mint(OWNER, 2000e18);

        vm.prank(OWNER);
        mockFromVault.approve(address(wrapper), 2000e18);

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();
        params.account = OWNER; // Same account

        bytes32 hash = _setupPreApprovedHash(params);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0));

        mockEvc.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_RevertsIfHashNotPreApproved() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();

        // Calculate hash but DO NOT pre-approve it
        bytes32 hash = wrapper.getApprovalHash(params);

        // Set operator permissions (required for EVC batch operations)
        mockEvc.setOperator(OWNER, address(wrapper), true);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, new bytes(0)); // Empty signature triggers pre-approved hash flow

        // Expect revert with HashNotApproved error
        vm.prank(SOLVER);
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.HashNotApproved.selector, OWNER, hash));
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_RevertsOnTamperedSignature() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = _getDefaultParams();
        // Use same account for owner and account to avoid subaccount validation
        params.account = OWNER;

        // Enable signature verification in MockEVC
        mockEvc.setSignatureVerification(true);

        // Create a private key and corresponding address for the owner
        uint256 ownerPrivateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address validOwner = vm.addr(ownerPrivateKey);

        // Update params to use the valid owner
        params.owner = validOwner;
        params.account = validOwner;

        // Build the signed calldata that will be included in the permit
        bytes memory signedCalldata = wrapper.encodePermitData(params);

        // Create the permit digest as MockEVC would expect it
        bytes32 permitStructHash = keccak256(
            abi.encode(
                keccak256(
                    "Permit(address signer,address sender,uint256 nonceNamespace,uint256 nonce,uint256 deadline,uint256 value,bytes data)"
                ),
                validOwner, // signer
                address(wrapper), // sender
                uint256(uint160(address(wrapper))), // nonceNamespace
                0, // nonce
                params.deadline, // deadline
                0, // value
                keccak256(signedCalldata) // data hash
            )
        );

        // Get domain separator from MockEVC
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("Ethereum Vault Connector"),
                block.chainid,
                address(mockEvc)
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, permitStructHash));

        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);

        // Tamper with the signature by flipping a bit in the r value
        bytes memory tamperedSignature = abi.encodePacked(bytes32(uint256(r) ^ 1), s, v);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = _encodeWrapperData(params, tamperedSignature);

        mockEvc.setSuccessfulBatch(true);

        // Expect revert with ECDSA error when signature is tampered
        vm.prank(SOLVER);
        vm.expectRevert("ECDSA: invalid signature");
        wrapper.wrappedSettle(settleData, wrapperData);
    }

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

        mockSettlement.setSuccessfulSettle(true);

        wrapper.setExpectedEvcInternalSettleCall(
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

        mockEvc.setSuccessfulBatch(true);

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

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        bytes memory settleData = _getEmptySettleData();
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEvc.setSuccessfulBatch(true);
        mockFromVault.mint(1000 ether, OWNER);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        // Should build a batch with enableCollateral + evcInternalSettle (2 items)
    }
}
