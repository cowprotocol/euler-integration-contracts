// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";

import {Inbox, InboxLibrary} from "../../src/Inbox.sol";
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
    address immutable ACCOUNT = makeAddr("account");
    address immutable RECIPIENT = makeAddr("recipient");
    address immutable OTHER_USER = makeAddr("other user");

    // This struct represents the order data that is signed by a user of CoW Protocol
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
        inbox = Inbox(inboxFactory.getInbox(BENEFICIARY, ACCOUNT));

        // Give inbox some tokens
        mockToken.mint(address(inbox), 1000e18);

        // Set some debt that would need to be repaid
        mockVault.setDebt(BENEFICIARY, 500e18);
    }

    // ============== InboxConstants Tests ==============

    function test_InboxLibrary_DomainTypeHashMatchesCoWSettlement() public pure {
        // This constant must match the EIP-712 domain separator type hash used by CoW Protocol
        // Verification look at the code here: https://etherscan.io/address/0x9008D19f58AAbD9eD0D60971565AA8510560ab41#code
        // Take the constant of the same name in `GPv2Signing.sol` and copy its value `chisel` REPL to get the below hash
        bytes32 expectedDomainTypeHash = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
        assertEq(
            InboxLibrary.DOMAIN_TYPE_HASH,
            expectedDomainTypeHash,
            "DOMAIN_TYPE_HASH does not match CoW Protocol settlement contract"
        );
    }

    function test_InboxLibrary_OrderTypeHashMatchesCoWSettlement() public pure {
        // This constant must match the EIP-712 domain separator type hash used by CoW Protocol
        // Verification: https://etherscan.io/address/0x9008D19f58AAbD9eD0D60971565AA8510560ab41#code
        // Take the constant from `GPv2Order` `TYPE_HASH`.
        bytes32 expectedOrderTypeHash = 0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489;
        assertEq(
            InboxLibrary.ORDER_TYPE_HASH,
            expectedOrderTypeHash,
            "ORDER_TYPE_HASH does not match CoW Protocol settlement contract"
        );
    }

    // ============== Constructor Tests ==============

    function test_Constructor_SetsMutablesCorrectly() public view {
        assertEq(inbox.OPERATOR(), address(inboxFactory), "OPERATOR not set");
        assertEq(inbox.BENEFICIARY(), BENEFICIARY, "BENEFICIARY not set");
        assertEq(inbox.SETTLEMENT(), address(mockSettlement), "SETTLEMENT not set");
        (, bytes32 inboxDomainSeparator) = inboxFactory.getInboxAddressAndDomainSeparator(BENEFICIARY, ACCOUNT);
        assertEq(inbox.INBOX_DOMAIN_SEPARATOR(), inboxDomainSeparator, "INBOX_DOMAIN_SEPARATOR not set");
    }

    function test_Constructor_SetsToActualSettlementContractDomainSeparatorCorrectly() public {
        // Verifies the computed domain separator in the Inbox matches the hash used by CoW Protocol
        // https://etherscan.io/address/0x9008D19f58AAbD9eD0D60971565AA8510560ab41#readContract#F2
        inboxFactory = new InboxFactory(address(0x9008D19f58AAbD9eD0D60971565AA8510560ab41));
        vm.chainId(1);
        inbox = Inbox(inboxFactory.getInbox(BENEFICIARY, ACCOUNT));
        bytes32 expectedSettlementDomainSeparator = 0xc078f884a2676e1345748b1feace7b0abee5d00ecadb6e574dcdd109a63e8943;

        assertEq(
            inbox.SETTLEMENT_DOMAIN_SEPARATOR(),
            expectedSettlementDomainSeparator,
            "SETTLEMENT_DOMAIN_SEPARATOR not set correctly"
        );
    }

    function test_InboxFactory_GetInboxCreationCode() public view {
        assertEq(inboxFactory.getInboxCreationCode(), type(Inbox).creationCode, "Creation code does not match");
    }

    function testFuzz_InboxFactory_ViewFunctionReturnsCorrectValues(address beneficiary, address account) public {
        (address computedAddress, bytes32 domainSeparator) =
            inboxFactory.getInboxAddressAndDomainSeparator(beneficiary, account);

        address createdInbox = inboxFactory.getInbox(beneficiary, account);

        require(createdInbox.code.length > 0, "Inbox not deployed to expected address");

        assertEq(computedAddress, createdInbox, "Creation address doesnt match");
        assertEq(domainSeparator, Inbox(createdInbox).INBOX_DOMAIN_SEPARATOR(), "Domain separator mismatch");
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
        vm.prank(address(inboxFactory));
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 1000e18, "Approval not set");
    }

    function test_CallApprove_ByBeneficiary() public {
        vm.prank(BENEFICIARY);
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);

        assertEq(mockToken.allowance(address(inbox), RECIPIENT), 1000e18, "Approval not set");
    }

    function test_CallApprove_RevertsIfCalledByUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        vm.prank(OTHER_USER);
        inbox.callApprove(address(mockToken), RECIPIENT, 1000e18);
    }

    function test_CallApprove_AllowsZeroAmount() public {
        vm.prank(address(inboxFactory));
        inbox.callApprove(address(mockToken), RECIPIENT, 0);

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
        vm.prank(address(inboxFactory));
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);

        assertEq(mockToken.balanceOf(RECIPIENT), 500e18, "Tokens not transferred");
        assertEq(mockToken.balanceOf(address(inbox)), 500e18, "Inbox balance not decreased");
    }

    function test_CallTransfer_ByBeneficiary() public {
        vm.prank(BENEFICIARY);
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);

        assertEq(mockToken.balanceOf(RECIPIENT), 500e18, "Tokens not transferred");
    }

    function test_CallTransfer_RevertsIfCalledByUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        vm.prank(OTHER_USER);
        inbox.callTransfer(address(mockToken), RECIPIENT, 500e18);
    }

    function test_CallTransfer_PassesThroughRevert() public {
        vm.prank(address(inboxFactory));
        vm.expectRevert("ERC20Mock: insufficient balance");
        inbox.callTransfer(address(mockToken), RECIPIENT, 1500e18);
    }

    // ============== callVaultRepay Tests ==============

    function test_CallVaultRepay_ByOperator() public {
        vm.expectCall(
            address(mockToken), abi.encodeWithSelector(MockERC20.approve.selector, address(mockVault), 500e18)
        );
        vm.expectCall(address(mockVault), abi.encodeWithSelector(MockBorrowVault.repay.selector, 500e18, BENEFICIARY));
        vm.prank(address(inboxFactory));
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
    }

    function test_CallVaultRepay_ByBeneficiary() public {
        vm.prank(BENEFICIARY);
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
    }

    function test_CallVaultRepay_RevertsIfCalledByUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        vm.prank(OTHER_USER);
        inbox.callVaultRepay(address(mockVault), address(mockToken), 500e18, BENEFICIARY);
    }

    // ============== setPreSignature Tests ==============

    function test_SetPreSignature_ByBeneficiary() public {
        bytes memory orderUid = abi.encodePacked(bytes32(0), address(0), uint32(0));

        vm.prank(BENEFICIARY);
        inbox.setPreSignature(orderUid, true);

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

        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, inboxFactory));
        vm.prank(address(inboxFactory));
        inbox.setPreSignature(orderUid, true);
    }

    function test_SetPreSignature_RevertsIfCalledByUnauthorized() public {
        bytes memory orderUid = abi.encodePacked(bytes32(0), address(0), uint32(0));

        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, OTHER_USER));
        vm.prank(OTHER_USER);
        inbox.setPreSignature(orderUid, true);
    }

    // ============== isValidSignature Tests ==============

    function testFuzz_IsValidSignature_ValidSignatureReturnsCorrectMagicValue(MockOrder memory mockOrder) public view {
        // Create a mock valid signature and order data
        (bytes32 orderDigest, bytes memory signatureData) = _createValidSignature(mockOrder);

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

    function testFuzz_IsValidSignature_RevertsIfSignerIsNotBeneficiary(MockOrder memory mockOrder) public {
        // Create a signature with the wrong signer
        bytes memory orderData = _createMockOrderData(mockOrder);
        (bytes32 settlementOrderDigest, bytes32 inboxOrderDigest) = _getOrderDigests(orderData);

        // Sign with a different private key (not BENEFICIARY)
        uint256 wrongPrivateKey = 999;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, inboxOrderDigest);

        bytes memory signatureData = abi.encodePacked(r, s, v, orderData);

        vm.expectRevert(abi.encodeWithSelector(Inbox.Unauthorized.selector, vm.addr(wrongPrivateKey)));
        inbox.isValidSignature(settlementOrderDigest, signatureData);
    }

    function testFuzz_IsValidSignature_RevertsOnOrderDigestMismatch(MockOrder memory mockOrder) public {
        bytes32 wrongDigest = keccak256("wrong");
        (bytes32 rightDigest, bytes memory signatureData) = _createValidSignature(mockOrder);

        vm.expectRevert(abi.encodeWithSelector(Inbox.OrderHashMismatch.selector, rightDigest, wrongDigest));
        inbox.isValidSignature(wrongDigest, signatureData);
    }

    // ============== Helper Functions ==============

    function _createValidSignature(MockOrder memory mockOrder)
        internal
        view
        returns (bytes32 orderDigest, bytes memory signatureData)
    {
        // Create mock order data (384 bytes)
        bytes memory orderData = _createMockOrderData(mockOrder);

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

    function _createMockOrderData(MockOrder memory order) internal view returns (bytes memory) {
        // Manually construct the structure matching EIP-712 Order encoding
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
        bytes32 typeHash = InboxLibrary.ORDER_TYPE_HASH;

        // Compute struct hash with order data prepended with type hash
        assembly {
            mstore(orderData, typeHash)
            structHash := keccak256(orderData, 416)
            mstore(orderData, 384) // restore original length
        }
    }
}
