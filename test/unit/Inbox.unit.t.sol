// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

import {Inbox} from "../../src/Inbox.sol";
import {MockCowSettlement, MockCowAuthentication} from "./mocks/MockCowProtocol.sol";
import {MockERC20, MockBorrowVault} from "./mocks/MockERC20AndVaults.sol";

contract InboxUnitTest is Test {
    Inbox public inbox;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;
    MockERC20 public mockToken;
    MockBorrowVault public mockVault;

    address constant OPERATOR = address(0x1111);
    address constant BENEFICIARY = address(0x2222);
    address constant RECIPIENT = address(0x3333);
    address constant OTHER_USER = address(0x4444);

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

    function setUp() public {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockToken = new MockERC20("Mock Token", "MOCK");
        mockVault = new MockBorrowVault(address(mockToken), "Mock Vault", "mMOCK");

        inbox = new Inbox(OPERATOR, BENEFICIARY, address(mockSettlement));
    }

    // ============== Constructor Tests ==============

    function test_Constructor_SetsMutablesCorrectly() public view {
        assertEq(inbox.OPERATOR(), OPERATOR, "OPERATOR not set");
        assertEq(inbox.BENEFICIARY(), BENEFICIARY, "BENEFICIARY not set");
        assertEq(inbox.SETTLEMENT(), address(mockSettlement), "SETTLEMENT not set");
    }

    function test_Constructor_SetsDomainSeparators() public view {
        // Verify that domain separators are computed correctly
        bytes32 expectedInboxDomain =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, keccak256("Inbox"), keccak256("1"), block.chainid, address(inbox)));
        assertEq(inbox.INBOX_DOMAIN_SEPARATOR(), expectedInboxDomain, "INBOX_DOMAIN_SEPARATOR incorrect");

        bytes32 expectedSettlementDomain = keccak256(
            abi.encode(
                DOMAIN_TYPE_HASH, keccak256("Gnosis Protocol"), keccak256("v2"), block.chainid, address(mockSettlement)
            )
        );
        assertEq(inbox.SETTLEMENT_DOMAIN_SEPARATOR(), expectedSettlementDomain, "SETTLEMENT_DOMAIN_SEPARATOR incorrect");
    }

    // ============== callApprove Tests ==============

    function test_CallApprove_ByOperator() public {
        vm.startPrank(OPERATOR);
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
        vm.startPrank(OPERATOR);
        inbox.callApprove(address(mockToken), RECIPIENT, 0);
        vm.stopPrank();

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 0, "Zero approval not set");
    }

    function test_CallApprove_UpdatesExistingApproval() public {
        vm.startPrank(OPERATOR);
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);
        inbox.callApprove(address(mockToken), RECIPIENT, 2000e18);
        vm.stopPrank();

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 2000e18, "Approval not updated");
    }

    // ============== callTransfer Tests ==============

    function test_CallTransfer_ByOperator() public {
        // Setup: give inbox some tokens
        mockToken.mint(address(inbox), 1000e18);

        vm.startPrank(OPERATOR);
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

    function test_CallTransfer_RevertsIfInsufficientBalance() public {
        mockToken.mint(address(inbox), 100e18);

        vm.startPrank(OPERATOR);
        vm.expectRevert();
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);
        vm.stopPrank();
    }

    // ============== callVaultRepay Tests ==============

    function test_CallVaultRepay_ByOperator() public {
        mockToken.mint(address(inbox), 1000e18);
        mockVault.setDebt(BENEFICIARY, 500e18);

        vm.startPrank(OPERATOR);
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
        vm.stopPrank();

        // Verify approval was set
        assertEq(mockToken.allowance(address(inbox), address(mockVault)), 500e18, "Approval not set for vault");

        // Verify repay was called
        assertEq(mockVault.repayCallCount(), 1, "repay not called");
        assertEq(mockVault.debtOf(BENEFICIARY), 0, "Debt not repaid");
    }

    function test_CallVaultRepay_ByBeneficiary() public {
        mockToken.mint(address(inbox), 1000e18);
        mockVault.setDebt(BENEFICIARY, 500e18);

        vm.startPrank(BENEFICIARY);
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
        vm.stopPrank();

        assertEq(mockVault.repayCallCount(), 1, "repay not called");
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

        vm.startPrank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OPERATOR));
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

        vm.expectRevert(abi.encodeWithSelector(Inbox.InvalidSignatureOrderData.selector, new bytes(0)));
        inbox.isValidSignature(orderDigest, invalidSignature);
    }

    function test_IsValidSignature_RevertsOnInsufficientOrderData() public {
        bytes32 orderDigest = keccak256("order");
        bytes memory insufficientData = new bytes(65 + 100); // 65 sig + 100 order (need 384)

        vm.expectRevert(abi.encodeWithSelector(Inbox.InvalidSignatureOrderData.selector));
        inbox.isValidSignature(orderDigest, insufficientData);
    }

    function test_IsValidSignature_RevertsIfSignerIsNotBeneficiary() public {
        // Create a signature with the wrong signer
        bytes memory orderData = _createMockOrderData();
        bytes32 structHash = _getOrderStructHash(orderData);
        bytes32 inboxOrderDigest = keccak256(abi.encodePacked("\x19\x01", inbox.INBOX_DOMAIN_SEPARATOR(), structHash));
        bytes32 settlementOrderDigest =
            keccak256(abi.encodePacked("\x19\x01", inbox.SETTLEMENT_DOMAIN_SEPARATOR(), structHash));

        // Sign with a different private key (not BENEFICIARY)
        uint256 wrongPrivateKey = 999;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, inboxOrderDigest);

        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory signatureData = abi.encodePacked(signature, orderData);

        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector));
        inbox.isValidSignature(settlementOrderDigest, signatureData);
    }

    function test_IsValidSignature_RevertsOnOrderDigestMismatch() public {
        bytes32 wrongDigest = keccak256("wrong");
        (, bytes memory signatureData) = _createValidSignature();

        vm.expectRevert(abi.encodeWithSelector(Inbox.OrderHashMismatch.selector));
        inbox.isValidSignature(wrongDigest, signatureData);
    }

    // ============== Helper Functions ==============

    function _createValidSignature() internal view returns (bytes32 orderDigest, bytes memory signatureData) {
        // Create mock order data (416 bytes)
        bytes memory orderData = _createMockOrderData();

        // Compute the inbox order digest
        bytes32 inboxOrderDigest = _hashInboxOrder();

        // Compute settlement order digest (with settlement domain separator)
        bytes32 settlementOrderDigest = keccak256(
            abi.encodePacked("\x19\x01", inbox.SETTLEMENT_DOMAIN_SEPARATOR(), _getOrderStructHash(orderData))
        );

        // Sign with beneficiary
        uint256 beneficiaryPrivateKey = uint256(uint160(BENEFICIARY));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(beneficiaryPrivateKey, inboxOrderDigest);

        bytes memory signature = abi.encodePacked(r, s, v);
        signatureData = abi.encodePacked(signature, orderData);

        return (settlementOrderDigest, signatureData);
    }

    function _hashInboxOrder() internal view returns (bytes32) {
        bytes memory orderData = _createMockOrderData();
        bytes32 structHash = _getOrderStructHash(orderData);

        return keccak256(abi.encodePacked("\x19\x01", inbox.INBOX_DOMAIN_SEPARATOR(), structHash));
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
        return abi.encodePacked(
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
        }
    }
}
