// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

/// @title PreApprovedHashes
/// @notice Abstract contract for managing pre-approved operation hashes
/// @dev Allows users to pre-approve specific operations without requiring signatures each time
abstract contract PreApprovedHashes {
    /// @dev Marker value indicating a hash is pre-approved
    uint256 private constant PRE_APPROVED = uint256(keccak256("CowEvcWrapper.PreApproved"));
    uint256 private constant CONSUMED_PRE_APPROVED = uint256(keccak256("CowEvcWrapper.Consumed"));

    /// @notice Storage indicating whether or not a signed calldata hash has been approved by an owner
    /// @dev Maps owner -> hash(signedCalldata) -> approval status
    mapping(address => mapping(bytes32 => uint256)) public preApprovedHashes;

    /// @notice Event emitted when an owner pre-approves or revokes a hash
    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);

    /// @notice Pre-approve a hash of signed calldata for future execution
    /// @dev Once a hash is pre-approved, it can only be consumed once. This prevents replay attacks.
    /// @param hash The keccak256 hash of the signed calldata
    /// @param approved True to approve the hash, false to revoke approval
    function setPreApprovedHash(bytes32 hash, bool approved) external {
        if (approved) {
            preApprovedHashes[msg.sender][hash] = PRE_APPROVED;
        } else {
            preApprovedHashes[msg.sender][hash] = 0;
        }
        emit PreApprovedHash(msg.sender, hash, approved);
    }

    /// @notice Check if a hash is pre-approved for an owner
    /// @param owner The owner address
    /// @param hash The hash to check
    /// @return True if the hash is pre-approved, false otherwise
    function isHashPreApproved(address owner, bytes32 hash) external view returns (bool) {
        return preApprovedHashes[owner][hash] == PRE_APPROVED;
    }

    /// @notice Check if a hash is pre-approved for an owner. If it is, changes it to be consumed, and returns true.
    /// @param owner The owner address
    /// @param hash The hash to check
    /// @return True if the hash was pre-approved and marked as consumed, false otherwise
    function _consumePreApprovedHash(address owner, bytes32 hash) internal returns (bool) {
        if (preApprovedHashes[owner][hash] == PRE_APPROVED) {
            preApprovedHashes[owner][hash] = CONSUMED_PRE_APPROVED;
            return true;
        } else {
            return false;
        }
    }
}
