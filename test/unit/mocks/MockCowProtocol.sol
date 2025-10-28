// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {CowSettlement, CowAuthentication} from "../../../src/vendor/CowWrapper.sol";

/// @title MockCowAuthentication
/// @notice Mock implementation of CoW Protocol authenticator for unit testing
contract MockCowAuthentication is CowAuthentication {
    mapping(address => bool) public solvers;

    function setSolver(address solver, bool authorized) external {
        solvers[solver] = authorized;
    }

    function isSolver(address prospectiveSolver) external view override returns (bool) {
        return solvers[prospectiveSolver];
    }
}

/// @title MockCowSettlement
/// @notice Mock implementation of CoW Protocol settlement contract for unit testing
contract MockCowSettlement is CowSettlement {
    CowAuthentication public immutable auth;
    bool public shouldSucceed = true;

    constructor(address _auth) {
        auth = CowAuthentication(_auth);
    }

    function authenticator() external view override returns (CowAuthentication) {
        return auth;
    }

    function vaultRelayer() external pure override returns (address) {
        return address(0x7777);
    }

    function domainSeparator() external pure override returns (bytes32) {
        return keccak256("MockDomainSeparator");
    }

    function setPreSignature(bytes calldata, bool) external pure override {}

    function settle(
        address[] calldata,
        uint256[] calldata,
        CowTradeData[] calldata,
        CowInteractionData[][3] calldata
    ) external view override {
        require(shouldSucceed, "MockCowSettlement: settle failed");
    }

    function setSuccessfulSettle(bool success) external {
        shouldSucceed = success;
    }
}
