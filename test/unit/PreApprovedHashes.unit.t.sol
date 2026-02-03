// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {Test} from "forge-std/Test.sol";
import {PreApprovedHashes} from "../../src/PreApprovedHashes.sol";

/// @title Unit tests for PreApprovedHashes
/// @notice Tests the pre-approved hash management functionality
contract PreApprovedHashesUnitTest is Test {
    TestablePreApprovedHashes public c;

    address constant USER = address(0x1111);
    address constant OTHER_USER = address(0x2222);

    function setUp() public {
        c = new TestablePreApprovedHashes();
    }

    /*//////////////////////////////////////////////////////////////
                        SET PRE-APPROVED HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetPreApprovedHash_EmitsEvent() public {
        bytes32 hash = keccak256("test");

        vm.expectEmit();
        emit PreApprovedHashes.PreApprovedHash(USER, hash, true);

        vm.prank(USER);
        c.setPreApprovedHash(hash, true);

        vm.expectEmit();
        emit PreApprovedHashes.PreApprovedHash(USER, hash, false);

        vm.prank(USER);
        c.setPreApprovedHash(hash, false);
    }

    function test_SetPreApprovedHash_CannotApproveConsumed() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        c.setPreApprovedHash(hash, true);

        // Consume the hash
        c.consumeHash(USER, hash);

        // Try to approve the consumed hash again
        vm.prank(USER);
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.AlreadyConsumed.selector, USER, hash));
        c.setPreApprovedHash(hash, true);
    }

    function test_SetPreApprovedHash_CannotRevokeConsumed() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        c.setPreApprovedHash(hash, true);

        // Consume the hash
        c.consumeHash(USER, hash);

        // Try to revoke the consumed hash
        vm.prank(USER);
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.AlreadyConsumed.selector, USER, hash));
        c.setPreApprovedHash(hash, false);
    }

    /*//////////////////////////////////////////////////////////////
                    CONSUME PRE-APPROVED HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConsumePreApprovedHash_EmitsEvent() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        c.setPreApprovedHash(hash, true);

        vm.expectEmit();
        emit PreApprovedHashes.PreApprovedHashConsumed(USER, hash);

        c.consumeHash(USER, hash);
    }

    function test_ConsumePreApprovedHash_CannotConsumedTwice() public {
        bytes32 hash = keccak256("test");

        vm.prank(USER);
        c.setPreApprovedHash(hash, true);

        // First consumption succeeds
        c.consumeHash(USER, hash);

        // Second consumption attempt should revert
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.AlreadyConsumed.selector, USER, hash));
        c.consumeHash(USER, hash);
    }

    /*//////////////////////////////////////////////////////////////
                        STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PreApprovedHashesStorage() public {
        bytes32 hash = keccak256("test");

        // Initially 0
        assertEq(c.preApprovedHashes(USER, hash), 0, "Should be 0 initially");

        // After approval, non-zero
        vm.prank(USER);
        c.setPreApprovedHash(hash, true);
        uint256 approvedValue = c.preApprovedHashes(USER, hash);
        assertGt(approvedValue, 0, "Should be non-zero after approval");

        // After revocation, its CONSUMED
        vm.prank(USER);
        c.setPreApprovedHash(hash, false);
        assertEq(
            c.preApprovedHashes(USER, hash),
            uint256(keccak256("PreApprovedHashes.Consumed")),
            "Should be 0 after revocation"
        );

        // You can't re-approve because its consumed
        vm.prank(USER);
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.AlreadyConsumed.selector, USER, hash));
        c.setPreApprovedHash(hash, true);
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetPreApprovedHash(address owner, bytes32 hash) public {
        vm.assume(owner != address(0));

        vm.prank(owner);
        c.setPreApprovedHash(hash, true);

        assertTrue(c.isHashPreApproved(owner, hash), "Hash should be approved");

        vm.prank(owner);
        c.setPreApprovedHash(hash, false);

        assertFalse(c.isHashPreApproved(owner, hash), "Hash should no longer be approved");
    }

    function testFuzz_ConsumePreApprovedHash(address owner, bytes32 hash) public {
        vm.assume(owner != address(0));

        vm.prank(owner);
        c.setPreApprovedHash(hash, true);

        // First consumption succeeds
        c.consumeHash(owner, hash);

        // Second consumption should revert
        vm.expectRevert(abi.encodeWithSelector(PreApprovedHashes.AlreadyConsumed.selector, owner, hash));
        c.consumeHash(owner, hash);
    }

    function testFuzz_MultipleUsersAndHashes(address user1, address user2, bytes32 hash1, bytes32 hash2) public {
        vm.assume(user1 != address(0) && user2 != address(0));
        vm.assume(user1 != user2);
        vm.assume(hash1 != hash2);

        vm.prank(user1);
        c.setPreApprovedHash(hash1, true);

        vm.prank(user2);
        c.setPreApprovedHash(hash2, true);

        assertTrue(c.isHashPreApproved(user1, hash1), "User1 hash1 should be approved");
        assertTrue(c.isHashPreApproved(user2, hash2), "User2 hash2 should be approved");

        assertFalse(c.isHashPreApproved(user1, hash2), "User1 should not have user2's hash");
        assertFalse(c.isHashPreApproved(user2, hash1), "User2 should not have user1's hash");
    }
}

/// @notice Testable version of PreApprovedHashes that exposes internal functions
contract TestablePreApprovedHashes is PreApprovedHashes {
    function consumeHash(address owner, bytes32 hash) external {
        _consumePreApprovedHash(owner, hash);
    }
}
