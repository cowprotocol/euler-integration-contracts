// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";
import {IERC20} from "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICowSettlement} from "./CowWrapper.sol";

/// @notice A contract for receiving funds from the CoW Settlement contract which can then be operated upon by a different contract in post (i.e. a wrapper)
/// @dev The contract has two associated accounts-- the OWNER, and the BENEFICIARY. Both associated accounts have the ability to execute token operations against this contract.
/// The purpose of the OWNER is to allow the wrapper to execute whatever operations it needs following a settlement contract operation without needing to store in the wrapper itself (ex. potentially intermingled with other user's funds) or the user's own wallet.
/// The purpose of the BENEFICIARY is to allow the ultimate holder of the funds to be able to access this contract in the case of trouble (ex. funds got stuck, etc.)
contract Inbox is IERC1271 {
    using SafeERC20 for IERC20;

    error Unauthorized(address);
    error OrderHashMismatch(bytes32 computed, bytes32 provided);

    bytes32 public immutable INBOX_DOMAIN_SEPARATOR;
    bytes32 public immutable SETTLEMENT_DOMAIN_SEPARATOR;

    /// @dev EIP-712 type hashes. These hashes match those used by the CoW settlement contract.
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant ORDER_TYPE_HASH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    );

    address public immutable OWNER;
    address public immutable BENEFICIARY;
    address public immutable SETTLEMENT;

    constructor(address owner, address beneficiary, address settlement) {
        OWNER = owner;
        BENEFICIARY = beneficiary;
        SETTLEMENT = settlement;

        INBOX_DOMAIN_SEPARATOR = keccak256(
            abi.encode(DOMAIN_TYPE_HASH, keccak256(bytes("Inbox")), keccak256(bytes("1")), block.chainid, address(this))
        );

        SETTLEMENT_DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPE_HASH, keccak256(bytes("Gnosis Protocol")), keccak256(bytes("v2")), block.chainid, settlement
            )
        );
    }

    /// @notice Implements EIP1271 `isValidSignature` to effectively allow this contract to operate in the same way as the user's signature
    /// @dev This code was copied from `GPv2Signer`'s' `ecdsaRecover` function. The idea is that the same signature the user would use
    /// for a regular CoW order is also used here.
    function isValidSignature(bytes32 orderDigest, bytes calldata signatureData)
        external
        view
        returns (bytes4 magicValue)
    {
        bytes32 amendedOrderDigest;
        {
            bytes memory orderData = signatureData[65:];
            bytes32 typeHash = ORDER_TYPE_HASH;
            bytes32 structHash;

            // NOTE: Compute the EIP-712 order struct hash in place. As suggested
            // in the EIP proposal, noting that the order struct has 12 fields, and
            // prefixing the type hash `(1 + 12) * 32 = 416` bytes to hash.
            // <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#rationale-for-encodedata>
            // solhint-disable-next-line no-inline-assembly
            assembly {
                mstore(orderData, typeHash)
                structHash := keccak256(orderData, 416)
            }

            bytes32 settlementDomainSeparator = SETTLEMENT_DOMAIN_SEPARATOR;
            bytes32 inboxDomainSeparator = INBOX_DOMAIN_SEPARATOR;
            bytes32 checkOrderDigest;

            assembly {
                let freeMemoryPointer := mload(0x40)
                mstore(freeMemoryPointer, "\x19\x01")
                mstore(add(freeMemoryPointer, 34), structHash)
                mstore(add(freeMemoryPointer, 2), inboxDomainSeparator)
                amendedOrderDigest := keccak256(freeMemoryPointer, 66)
                mstore(add(freeMemoryPointer, 2), settlementDomainSeparator)
                checkOrderDigest := keccak256(freeMemoryPointer, 66)
            }

            if (checkOrderDigest != orderDigest) {
                revert OrderHashMismatch(checkOrderDigest, orderDigest);
            }
        }

        bytes calldata signature = signatureData[:65];

        bytes32 r;
        bytes32 s;
        uint8 v;

        // NOTE: Use assembly to efficiently decode signature data.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // r = uint256(signature[0:32])
            r := calldataload(signature.offset)
            // s = uint256(signature[32:64])
            s := calldataload(add(signature.offset, 32))
            // v = uint8(signature[64])
            v := shr(248, calldataload(add(signature.offset, 64)))
        }

        address signer = ecrecover(amendedOrderDigest, v, r, s);
        require(signer == BENEFICIARY, Unauthorized(signer));

        return bytes4(keccak256("isValidSignature(bytes32,bytes)"));
    }

    /// @notice Calls the settlement contract function with the same signature to set a pre signature on behalf of the Inbox
    /// @param orderUid The order uid to pre-approve
    /// @param approved Whether to approve or revoke approval
    function setPreSignature(bytes calldata orderUid, bool approved) external {
        require(msg.sender == BENEFICIARY, Unauthorized(msg.sender));

        ICowSettlement(SETTLEMENT).setPreSignature(orderUid, approved);
    }

    function callApprove(address token, address spender, uint256 amount) external {
        require(msg.sender == OWNER || msg.sender == BENEFICIARY, Unauthorized(msg.sender));
        IERC20(token).forceApprove(spender, amount);
    }

    /// @notice Transfers tokens from this contract to a recipient
    /// @param token The ERC20 token to transfer
    /// @param to The recipient address
    /// @param amount The amount to transfer
    function callTransfer(address token, address to, uint256 amount) external {
        require(msg.sender == OWNER || msg.sender == BENEFICIARY, Unauthorized(msg.sender));
        IERC20(token).safeTransfer(to, amount);
    }

    /// @notice Calls repay on a vault to repay debt from this contract's balance. Will also set the necessary approval for it to happen.
    /// @param vault The vault contract to call repay on
    /// @param amount The amount to repay
    /// @param account The account to repay debt for
    function callVaultRepay(address vault, address asset, uint256 amount, address account) external {
        require(msg.sender == OWNER || msg.sender == BENEFICIARY, Unauthorized(msg.sender));
        IERC20(asset).forceApprove(vault, amount);
        IBorrowing(vault).repay(amount, account);
    }
}
