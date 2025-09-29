// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "ethereum-vault-connector/EthereumVaultConnector.sol";

import "openzeppelin/utils/cryptography/ECDSA.sol";

abstract contract EIP712 {

    bytes32 internal constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

    bytes32 internal immutable _hashedName;
    string private _name;
    string private _nameFallback;

    /**
     * @dev Initializes the domain separator.
     *
     * The meaning of `name` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    constructor(string memory name) {
        _name = name;
        _hashedName = keccak256(bytes(name));
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() internal view virtual returns (bytes32) {
        return bytes32(0);
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}

contract SignerECDSA is EIP712, Test {
    EthereumVaultConnector private immutable evc;
    uint256 private privateKey;

    bytes32 internal constant PERMIT_TYPEHASH = keccak256(
        "Permit(address signer,address sender,uint256 nonceNamespace,uint256 nonce,uint256 deadline,uint256 value,bytes data)"
    );

    constructor(EthereumVaultConnector _evc) EIP712(_evc.name()) {
        evc = _evc;
    }

    function setPrivateKey(uint256 _privateKey) external {
        privateKey = _privateKey;
    }

    function _buildDomainSeparator() internal view override returns (bytes32) {
        return keccak256(abi.encode(_TYPE_HASH, _hashedName, block.chainid, address(evc)));
    }

    function signPermit(
        address signer,
        address sender,
        uint256 nonceNamespace,
        uint256 nonce,
        uint256 deadline,
        uint256 value,
        bytes calldata data
    ) external view returns (bytes memory signature) {
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, signer, sender, nonceNamespace, nonce, deadline, value, keccak256(data))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, _hashTypedDataV4(structHash));
        signature = abi.encodePacked(r, s, v);
    }
}
