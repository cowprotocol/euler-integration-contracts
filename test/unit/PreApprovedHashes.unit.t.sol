// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import "forge-std/Test.sol";
import {PreApprovedHashes} from "../../src/PreApprovedHashes.sol";

/// @title Unit tests for PreApprovedHashes
/// @notice Tests the pre-approved hash management functionality
contract PreApprovedHashesUnitTest is Test {
    TestablePreApprovedHashes public preApprovedHashes;

    address constant USER = address(0x1111);
    address constant OTHER_USER = address(0x2222);

    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    function setUp() public {
        preApprovedHashes = new TestablePreApprovedHashes();
    }

    /*//////////////////////////////////////////////////////////////
                        SET PRE-APPROVED HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetPreApprovedHash_EmitsEvent() public {
        bytes32 hash = keccak256("test");

        vm.expectEmit(true, true, false, true);
        emit PreApprovedHash(USER, hash, true);

        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, true);

        vm.expectEmit(true, true, false, true);
        emit PreApprovedHash(USER, hash, false);

        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, false);
    }

    function test_SetPreApprovedHash_CannotApproveConsumed() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, true);

        // Consume the hash
        preApprovedHashes.testConsumeHash(USER, hash);

        // Try to approve the consumed hash again
        vm.prank(USER);
        vm.expectRevert(abi.encodeWithSignature("AlreadyConsumed(address,bytes32)", USER, hash));
        preApprovedHashes.setPreApprovedHash(hash, true);
    }

    function test_SetPreApprovedHash_CannotRevokeConsumed() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, true);

        // Consume the hash
        preApprovedHashes.testConsumeHash(USER, hash);

        // Try to revoke the consumed hash
        vm.prank(USER);
        vm.expectRevert(abi.encodeWithSignature("AlreadyConsumed(address,bytes32)", USER, hash));
        preApprovedHashes.setPreApprovedHash(hash, false);
    }

    function test_SetPreApprovedHash_RevokeAndReapprove() public {
        bytes32 hash = keccak256("test");

        vm.startPrank(USER);

        // Approve
        preApprovedHashes.setPreApprovedHash(hash, true);
        assertGt(preApprovedHashes.preApprovedHashes(USER, hash), 0, "Hash should be approved");

        // Revoke
        preApprovedHashes.setPreApprovedHash(hash, false);
        assertEq(preApprovedHashes.preApprovedHashes(USER, hash), 0, "Hash should not be approved");

        // Reapprove
        preApprovedHashes.setPreApprovedHash(hash, true);
        assertGt(preApprovedHashes.preApprovedHashes(USER, hash), 0, "Hash should be approved again");

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    CONSUME PRE-APPROVED HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConsumePreApprovedHash_EmitsEvent() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, true);

        vm.expectEmit(true, true, false, true);
        emit PreApprovedHashConsumed(USER, hash);

        preApprovedHashes.testConsumeHash(USER, hash);
    }

    function test_ConsumePreApprovedHash_CannotConsumedTwice() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, true);

        // First consumption
        bool consumed1 = preApprovedHashes.testConsumeHash(USER, hash);
        assertTrue(consumed1, "First consumption should succeed");

        // Second consumption attempt
        bool consumed2 = preApprovedHashes.testConsumeHash(USER, hash);
        assertFalse(consumed2, "Second consumption should fail");
    }

    /*//////////////////////////////////////////////////////////////
                        STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PreApprovedHashesStorage() public {
        bytes32 hash = keccak256("test");

        // Initially 0
        assertEq(preApprovedHashes.preApprovedHashes(USER, hash), 0, "Should be 0 initially");

        // After approval, non-zero
        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, true);
        uint256 approvedValue = preApprovedHashes.preApprovedHashes(USER, hash);
        assertGt(approvedValue, 0, "Should be non-zero after approval");

        // After revocation, back to 0
        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, false);
        assertEq(preApprovedHashes.preApprovedHashes(USER, hash), 0, "Should be 0 after revocation");

        // After re-approval, non-zero again
        vm.prank(USER);
        preApprovedHashes.setPreApprovedHash(hash, true);
        assertGt(preApprovedHashes.preApprovedHashes(USER, hash), 0, "Should be non-zero after re-approval");

        // After consumption, different non-zero value
        preApprovedHashes.testConsumeHash(USER, hash);
        uint256 consumedValue = preApprovedHashes.preApprovedHashes(USER, hash);
        assertGt(consumedValue, 0, "Should be non-zero after consumption");
        assertNotEq(consumedValue, approvedValue, "Consumed value should differ from approved value");
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetPreApprovedHash(address owner, bytes32 hash) public {
        vm.assume(owner != address(0));

        vm.prank(owner);
        preApprovedHashes.setPreApprovedHash(hash, true);

        assertTrue(preApprovedHashes.isHashPreApproved(owner, hash), "Hash should be approved");

        vm.prank(owner);
        preApprovedHashes.setPreApprovedHash(hash, false);

        assertFalse(preApprovedHashes.isHashPreApproved(owner, hash), "Hash should no longer be approved");
    }

    function testFuzz_ConsumePreApprovedHash(address owner, bytes32 hash) public {
        vm.assume(owner != address(0));

        vm.prank(owner);
        preApprovedHashes.setPreApprovedHash(hash, true);

        bool consumed = preApprovedHashes.testConsumeHash(owner, hash);
        assertTrue(consumed, "Should successfully consume");

        bool consumedAgain = preApprovedHashes.testConsumeHash(owner, hash);
        assertFalse(consumedAgain, "Should not consume twice");
    }

    function testFuzz_MultipleUsersAndHashes(address user1, address user2, bytes32 hash1, bytes32 hash2) public {
        vm.assume(user1 != address(0) && user2 != address(0));
        vm.assume(user1 != user2);
        vm.assume(hash1 != hash2);

        vm.prank(user1);
        preApprovedHashes.setPreApprovedHash(hash1, true);

        vm.prank(user2);
        preApprovedHashes.setPreApprovedHash(hash2, true);

        assertTrue(preApprovedHashes.isHashPreApproved(user1, hash1), "User1 hash1 should be approved");
        assertTrue(preApprovedHashes.isHashPreApproved(user2, hash2), "User2 hash2 should be approved");

        assertFalse(preApprovedHashes.isHashPreApproved(user1, hash2), "User1 should not have user2's hash");
        assertFalse(preApprovedHashes.isHashPreApproved(user2, hash1), "User2 should not have user1's hash");
    }
}

/// @notice Testable version of PreApprovedHashes that exposes internal functions
contract TestablePreApprovedHashes is PreApprovedHashes {
    function testConsumeHash(address owner, bytes32 hash) external returns (bool) {
        return _consumePreApprovedHash(owner, hash);
    }
}
