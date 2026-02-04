// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

import {Inbox} from "../../src/Inbox.sol";
import {InboxFactory} from "../../src/InboxFactory.sol";
import {MockCowSettlement, MockCowAuthentication} from "./mocks/MockCowProtocol.sol";
import {MockERC20, MockBorrowVault} from "./mocks/MockERC20AndVaults.sol";

contract InboxUnitTest is Test {
    InboxFactory public inboxFactory;
    Inbox public inbox;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;
    MockERC20 public mockToken;
    MockBorrowVault public mockVault;

    uint256 immutable BENEFICIARY_PRIVATE_KEY;

    address immutable BENEFICIARY;
    address immutable RECIPIENT = makeAddr("recipient");
    address immutable OTHER_USER = makeAddr("other user");

    // EIP-712 constants from Inbox
    bytes32 constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );

    // Mock order data structure (416 bytes total)
    struct MockOrder {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        string kind;
        bool partiallyFillable;
        string sellTokenBalance;
        string buyTokenBalance;
    }

    constructor() {
        (BENEFICIARY, BENEFICIARY_PRIVATE_KEY) = makeAddrAndKey("beneficiary");
    }

    function setUp() public {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockToken = new MockERC20("Mock Token", "MOCK");
        mockVault = new MockBorrowVault(address(mockToken), "Mock Vault", "mMOCK");

        inboxFactory = new InboxFactory(address(mockSettlement));
        inbox = Inbox(inboxFactory.getInbox(BENEFICIARY, (address(this))));
    }

    // ============== Constructor Tests ==============

    function test_Constructor_SetsMutablesCorrectly() public view {
        assertEq(inbox.OPERATOR(), address(inboxFactory), "OPERATOR not set");
        assertEq(inbox.BENEFICIARY(), BENEFICIARY, "BENEFICIARY not set");
        assertEq(inbox.SETTLEMENT(), address(mockSettlement), "SETTLEMENT not set");
    }

    function test_InboxFactory_ViewFunctionReturnsCorrectValues() public view {
        (address computedAddress, bytes32 domainSeparator) =
            inboxFactory.getInboxAddressAndDomainSeparator(BENEFICIARY, address(this));

        assertEq(computedAddress, address(inbox), "Computed address mismatch");
        assertEq(domainSeparator, inbox.INBOX_DOMAIN_SEPARATOR(), "Domain separator mismatch");
    }

    // ============== getInbox Tests ==============
    function test_InboxFactory_GetInbox_ReturnsNewInboxForNewSubaccount() external {
        address newSubaccount = makeAddr("new subaccount");
        address newInboxAddress = inboxFactory.getInbox(BENEFICIARY, newSubaccount);

        assertTrue(newInboxAddress.code.length > 0, "Inbox not deployed");
        assertNotEq(newInboxAddress, address(inbox), "Inbox address should be different");
    }

    // ============== callApprove Tests ==============

    function test_CallApprove_ByOperator() public {
        vm.startPrank(address(inboxFactory));
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);
        vm.stopPrank();

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 1000e18, "Approval not set");
    }

    function test_CallApprove_ByBeneficiary() public {
        vm.startPrank(BENEFICIARY);
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);
        vm.stopPrank();

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 1000e18, "Approval not set");
    }

    function test_CallApprove_RevertsIfCalledByUnauthorized() public {
        vm.startPrank(OTHER_USER);
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);
        vm.stopPrank();
    }

    function test_CallApprove_AllowsZeroAmount() public {
        vm.startPrank(address(inboxFactory));
        inbox.callApprove(address(mockToken), RECIPIENT, 0);
        vm.stopPrank();

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 0, "Zero approval not set");
    }

    function test_CallApprove_UpdatesExistingApproval() public {
        vm.startPrank(address(inboxFactory));
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);
        inbox.callApprove(address(mockToken), RECIPIENT, 2000e18);
        vm.stopPrank();

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 2000e18, "Approval not updated");
    }

    // ============== callTransfer Tests ==============

    function test_CallTransfer_ByOperator() public {
        // Setup: give inbox some tokens
        mockToken.mint(address(inbox), 1000e18);

        vm.startPrank(address(inboxFactory));
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(RECIPIENT), 500e18, "Tokens not transferred");
        assertEq(mockToken.balanceOf(address(inbox)), 500e18, "Inbox balance not decreased");
    }

    function test_CallTransfer_ByBeneficiary() public {
        mockToken.mint(address(inbox), 1000e18);

        vm.startPrank(BENEFICIARY);
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(RECIPIENT), 500e18, "Tokens not transferred");
    }

    function test_CallTransfer_RevertsIfCalledByUnauthorized() public {
        mockToken.mint(address(inbox), 1000e18);

        vm.startPrank(OTHER_USER);
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);
        vm.stopPrank();
    }

    function test_CallTransfer_PassesThroughRevert() public {
        mockToken.mint(address(inbox), 100e18);

        vm.startPrank(address(inboxFactory));
        vm.expectRevert();
        // should be insufficient balance
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);
        vm.stopPrank();
    }

    // ============== callVaultRepay Tests ==============

    function test_CallVaultRepay_ByOperator() public {
        mockToken.mint(address(inbox), 1000e18);
        mockVault.setDebt(BENEFICIARY, 500e18);

        vm.startPrank(address(inboxFactory));
        vm.expectCall(
            address(mockToken), abi.encodeWithSelector(MockERC20.approve.selector, address(mockVault), 500e18)
        );
        vm.expectCall(address(mockVault), abi.encodeWithSelector(MockBorrowVault.repay.selector, 500e18, BENEFICIARY));
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
        vm.stopPrank();
    }

    function test_CallVaultRepay_ByBeneficiary() public {
        mockToken.mint(address(inbox), 1000e18);
        mockVault.setDebt(BENEFICIARY, 500e18);

        vm.startPrank(BENEFICIARY);
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
        vm.stopPrank();
    }

    function test_CallVaultRepay_RevertsIfCalledByUnauthorized() public {
        mockToken.mint(address(inbox), 1000e18);

        vm.startPrank(OTHER_USER);
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
        vm.stopPrank();
    }

    // ============== setPreSignature Tests ==============

    function test_SetPreSignature_ByBeneficiary() public {
        bytes memory orderUid = abi.encodePacked(bytes32(0), address(0), uint32(0));

        vm.startPrank(BENEFICIARY);
        inbox.setPreSignature(orderUid, true);
        vm.stopPrank();

        assertTrue(mockSettlement.preSignatures(orderUid), "Pre-signature not set");
    }

    function test_SetPreSignature_CanRevokeSignature() public {
        bytes memory orderUid = abi.encodePacked(bytes32(0), address(0), uint32(0));

        vm.startPrank(BENEFICIARY);
        inbox.setPreSignature(orderUid, true);
        inbox.setPreSignature(orderUid, false);
        vm.stopPrank();

        assertFalse(mockSettlement.preSignatures(orderUid), "Pre-signature not revoked");
    }

    function test_SetPreSignature_RevertsIfCalledByOperator() public {
        bytes memory orderUid = abi.encodePacked(bytes32(0), address(0), uint32(0));

        vm.startPrank(address(inboxFactory));
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, inboxFactory));
        inbox.setPreSignature(orderUid, true);
        vm.stopPrank();
    }

    function test_SetPreSignature_RevertsIfCalledByUnauthorized() public {
        bytes memory orderUid = abi.encodePacked(bytes32(0), address(0), uint32(0));

        vm.startPrank(OTHER_USER);
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        inbox.setPreSignature(orderUid, true);
        vm.stopPrank();
    }

    // ============== isValidSignature Tests ==============

    function test_IsValidSignature_ValidSignatureReturnsCorrectMagicValue() public view {
        // Create a mock valid signature and order data
        (bytes32 orderDigest, bytes memory signatureData) = _createValidSignature();

        bytes4 result = inbox.isValidSignature(orderDigest, signatureData);

        assertEq(result, bytes4(keccak256("isValidSignature(bytes32,bytes)")), "Invalid magic value");
    }

    function test_IsValidSignature_RevertsOnInvalidSignatureLength() public {
        bytes32 orderDigest = keccak256("order");
        bytes memory invalidSignature = new bytes(64); // Too short (needs 65 + 384)

        vm.expectRevert(abi.encodeWithSelector(Inbox.InvalidSignatureOrderData.selector, invalidSignature));
        inbox.isValidSignature(orderDigest, invalidSignature);
    }

    function test_IsValidSignature_RevertsOnInsufficientOrderData() public {
        bytes32 orderDigest = keccak256("order");
        bytes memory insufficientData = new bytes(65 + 383); // 65 sig + 383 order (need 384)

        vm.expectRevert(abi.encodeWithSelector(Inbox.InvalidSignatureOrderData.selector, insufficientData));
        inbox.isValidSignature(orderDigest, insufficientData);
    }

    function test_IsValidSignature_RevertsIfSignerIsNotBeneficiary() public {
        // Create a signature with the wrong signer
        bytes memory orderData = _createMockOrderData();
        (bytes32 settlementOrderDigest, bytes32 inboxOrderDigest) = _getOrderDigests(orderData);

        // Sign with a different private key (not BENEFICIARY)
        uint256 wrongPrivateKey = 999;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, inboxOrderDigest);

        bytes memory signatureData = abi.encodePacked(r, s, v, orderData);

        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, vm.addr(wrongPrivateKey)));
        inbox.isValidSignature(settlementOrderDigest, signatureData);
    }

    function test_IsValidSignature_RevertsOnOrderDigestMismatch() public {
        bytes32 wrongDigest = keccak256("wrong");
        (, bytes memory signatureData) = _createValidSignature();
        (bytes32 rightDigest,) = _getOrderDigests(_createMockOrderData());

        vm.expectRevert(abi.encodeWithSelector(Inbox.OrderHashMismatch.selector, rightDigest, wrongDigest));
        inbox.isValidSignature(wrongDigest, signatureData);
    }

    // ============== Helper Functions ==============

    function _createValidSignature() internal view returns (bytes32 orderDigest, bytes memory signatureData) {
        // Create mock order data (384 bytes)
        bytes memory orderData = _createMockOrderData();

        // Compute the inbox order digest
        (bytes32 settlementOrderDigest, bytes32 inboxOrderDigest) = _getOrderDigests(orderData);

        // Sign with beneficiary
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BENEFICIARY_PRIVATE_KEY, inboxOrderDigest);

        signatureData = abi.encodePacked(r, s, v, orderData);

        return (settlementOrderDigest, signatureData);
    }

    function _getOrderDigests(bytes memory orderData)
        internal
        view
        returns (bytes32 settlementHash, bytes32 inboxHash)
    {
        bytes32 structHash = _getOrderStructHash(orderData);

        return (
            keccak256(abi.encodePacked("\x19\x01", inbox.SETTLEMENT_DOMAIN_SEPARATOR(), structHash)),
            keccak256(abi.encodePacked("\x19\x01", inbox.INBOX_DOMAIN_SEPARATOR(), structHash))
        );
    }

    function _createMockOrderData() internal view returns (bytes memory) {
        // Create a 416 byte order data structure
        // This is the raw encoding of a CoW Order struct
        MockOrder memory order = MockOrder({
            sellToken: address(0x1),
            buyToken: address(0x2),
            receiver: address(0x3),
            sellAmount: 1000e18,
            buyAmount: 500e18,
            validTo: uint32(block.timestamp + 3600),
            appData: bytes32(0),
            feeAmount: 0,
            kind: "sell",
            partiallyFillable: false,
            sellTokenBalance: "erc20",
            buyTokenBalance: "erc20"
        });

        // Manually construct the 416-byte structure matching EIP-712 Order encoding
        return abi.encode(
            order.sellToken,
            order.buyToken,
            order.receiver,
            order.sellAmount,
            order.buyAmount,
            order.validTo,
            order.appData,
            order.feeAmount,
            keccak256(bytes(order.kind)),
            order.partiallyFillable,
            keccak256(bytes(order.sellTokenBalance)),
            keccak256(bytes(order.buyTokenBalance))
        );
    }

    function _getOrderStructHash(bytes memory orderData) internal pure returns (bytes32 structHash) {
        bytes32 typeHash = ORDER_TYPE_HASH;

        // Compute struct hash with order data prepended with type hash
        assembly {
            mstore(orderData, typeHash)
            structHash := keccak256(orderData, 416)
            mstore(orderData, 384) // restore original length
        }
    }
}
