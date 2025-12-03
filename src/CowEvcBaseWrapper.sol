// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";

import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {PreApprovedHashes} from "./PreApprovedHashes.sol";

/// @title CowEvcBaseWrapper
/// @notice Shared components for implementing Euler wrappers.
abstract contract CowEvcBaseWrapper is CowWrapper, PreApprovedHashes {
    IEVC public immutable EVC;

    /// @dev The EIP-712 domain type hash used for computing the domain
    /// separator.
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The marker value for a sell order for computing the order struct
    /// hash. This allows the EIP-712 compatible wallets to display a
    /// descriptive string for the order kind (instead of 0 or 1).
    bytes32 internal constant KIND_SELL = keccak256("sell");

    /// @dev The OrderKind marker value for a buy order for computing the order
    /// struct hash.
    bytes32 internal constant KIND_BUY = keccak256("buy");

    /// @dev Used by EIP-712 signing to prevent signatures from being replayed
    bytes32 public immutable DOMAIN_SEPARATOR;

    //// @dev The EVC nonce namespace to use when calling `EVC.permit` to authorize this contract.
    uint256 public immutable NONCE_NAMESPACE;

    uint256 internal immutable PARAMS_SIZE;

    /// @dev Indicates that the current operation cannot be completed with the given msgSender
    error Unauthorized(address msgSender);

    /// @dev Indicates that the pre-approved hash is no longer able to be executed because the block timestamp is too old
    error OperationDeadlineExceeded(uint256 validToTimestamp, uint256 currentTimestamp);

    /// @dev Indicates that this contract did not receive enough repayment assets from the settlement contract in order to cover all user's orders
    error InsufficientRepaymentAsset(address vault, uint256 balanceAmount, uint256 repayAmount);

    /// @dev Indicates that a user attempted to interact with an account that is not their own
    error SubaccountMustBeControlledByOwner(address subaccount, address owner);

    /// @dev Indicates that the EVC called `evcInternalSettle` in an invalid way
    error InvalidCallback();

    /// @dev Used to ensure that the EVC is calling back this contract with the correct data
    bytes32 internal transient expectedEvcInternalSettleCallHash;

    constructor(address _evc, ICowSettlement _settlement) CowWrapper(_settlement) {
        require(_evc.code.length > 0, "EVC address is invalid");
        EVC = IEVC(_evc);
        // forge-lint: disable-next-line(asm-keccak256)
        bytes32 domainNameHash = keccak256(bytes(domainName()));
        // forge-lint: disable-next-line(asm-keccak256)
        bytes32 domainVersionHash = keccak256(bytes(domainVersion()));
        NONCE_NAMESPACE = uint256(uint160(address(this)));
        DOMAIN_SEPARATOR =
            keccak256(abi.encode(DOMAIN_TYPE_HASH, domainNameHash, domainVersionHash, block.chainid, address(this)));
    }

    /// @dev This function makes strong assumptions on the memory layout of the struct in memory.
    /// It assumes:
    ///  - The struct itself doesn't contain any dynamic-length types.
    ///  - The struct is encoded in memory with zero padding.
    function _getApprovalHash(bytes32 paramsMemoryLocation) internal view returns (bytes32 digest) {
        bytes32 structHash;
        bytes32 separator = DOMAIN_SEPARATOR;
        uint256 paramsSize = PARAMS_SIZE;
        assembly ("memory-safe") {
            structHash := keccak256(paramsMemoryLocation, paramsSize)
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), separator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }

    /// @notice Internal settlement function called by EVC
    function evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) external payable {
        require(msg.sender == address(EVC), Unauthorized(msg.sender));
        require(expectedEvcInternalSettleCallHash == keccak256(msg.data), InvalidCallback());
        expectedEvcInternalSettleCallHash = bytes32(0);
        _evcInternalSettle(settleData, wrapperData, remainingWrapperData);
    }

    function _evcInternalSettle(
        bytes calldata settleData,
        bytes calldata wrapperData,
        bytes calldata remainingWrapperData
    ) internal virtual;

    /// @return The EIP-712 domain name used for computing the domain separator.
    function domainName() internal pure virtual returns (string memory);

    /// @return The EIP-712 domain version used for computing the domain separator.
    function domainVersion() internal pure virtual returns (string memory);
}
