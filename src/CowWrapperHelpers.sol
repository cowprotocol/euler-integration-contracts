// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {ICowAuthentication, ICowWrapper} from "./CowWrapper.sol";

/// @title CoW Protocol Wrapper Helpers
/// @notice Helper contract providing validation and encoding utilities for CoW Protocol wrapper chains
/// @dev This contract is not designed to be gas-efficient and is intended for off-chain use only.
contract CowWrapperHelpers {
    /// @notice Thrown when a provided address is not an authenticated wrapper
    /// @param wrapperIndex The index of the invalid wrapper in the array
    /// @param unauthorized The address that is not authenticated as a wrapper
    /// @param authenticatorContract The authentication contract that rejected the wrapper
    error WrapperNotAuthorized(uint256 wrapperIndex, address unauthorized, address authenticatorContract);

    /// @notice Thrown when a wrapper's validateWrapperData reverts, which is assumed to be due to malformed data
    /// @param wrapperIndex The index of the wrapper with malformed data
    /// @param wrapperError The error returned by the wrapper's validateWrapperData
    error WrapperDataMalformed(uint256 wrapperIndex, bytes wrapperError);

    /// @notice Thrown when the data for the wrapper is too long. Its limited to 65535 bytes.
    /// @param wrapperIndex The index of the wrapper with data that is too long
    /// @param exceedingLength The observed length of the data
    error WrapperDataTooLong(uint256 wrapperIndex, uint256 exceedingLength);

    /// @notice Thrown when the settlement contract is authenticated as a solver
    /// @dev The settlement contract should not be a solver to prevent direct settlement calls bypassing wrappers
    /// @param settlementContract The settlement contract address
    /// @param authenticatorContract The authentication contract that authenticated the settlement as a solver
    error SettlementContractShouldNotBeSolver(address settlementContract, address authenticatorContract);

    /// @notice Thrown when wrappers in the chain use different settlement contracts
    /// @param wrapperIndex The index of the wrapper with a mismatched settlement
    /// @param expectedSettlement The settlement contract used by the first wrapper
    /// @param actualSettlement The settlement contract used by this wrapper
    error SettlementMismatch(uint256 wrapperIndex, address expectedSettlement, address actualSettlement);

    /// @notice A definition for a single call to a wrapper
    /// @dev This corresponds to the `wrappers` item structure on the CoW Orderbook API
    struct WrapperCall {
        /// @notice The smart contract that will be receiving the call
        address target;

        /// @notice Any additional data which will be required to execute the wrapper call
        bytes data;
    }

    /// @notice The authentication contract used to verify wrapper contracts
    ICowAuthentication public immutable WRAPPER_AUTHENTICATOR;

    /// @notice Constructs a new CowWrapperHelpers contract
    /// @param wrapperAuthenticator_ The ICowAuthentication contract used to verify wrapper contracts
    constructor(ICowAuthentication wrapperAuthenticator_) {
        WRAPPER_AUTHENTICATOR = wrapperAuthenticator_;
    }

    /// @notice Validates a wrapper chain configuration and builds the properly formatted wrapper data
    /// @dev Performs comprehensive validation of the wrapper chain before encoding:
    ///      1. Verifies each wrapper is authenticated via WRAPPER_AUTHENTICATOR
    ///      2. Verifies each wrapper's data is valid and fully consumed by calling validateWrapperData
    ///      3. Verifies all wrappers use the same settlement contract (from first wrapper's SETTLEMENT)
    ///      4. Verifies the settlement contract is not authenticated as a solver
    /// See CowWrapper.wrappedSettle for more information about how the wrapper data chain is encoded
    /// @param wrapperCalls Array of calls in execution order
    /// @return chainedWrapperData The encoded wrapper data ready to be passed to the first wrapper's wrappedSettle
    function verifyAndBuildWrapperData(WrapperCall[] memory wrapperCalls)
        external
        view
        returns (bytes memory chainedWrapperData)
    {
        if (wrapperCalls.length == 0) {
            return chainedWrapperData;
        }

        for (uint256 i = 0; i < wrapperCalls.length; i++) {
            require(
                WRAPPER_AUTHENTICATOR.isSolver(wrapperCalls[i].target),
                WrapperNotAuthorized(i, wrapperCalls[i].target, address(WRAPPER_AUTHENTICATOR))
            );

            // The wrapper data must be parsable
            try ICowWrapper(wrapperCalls[i].target).validateWrapperData(wrapperCalls[i].data) {}
            catch (bytes memory err) {
                revert WrapperDataMalformed(i, err);
            }

            if (i > 0) {
                chainedWrapperData = abi.encodePacked(chainedWrapperData, wrapperCalls[i].target);
            }

            require(wrapperCalls[i].data.length < 65536, WrapperDataTooLong(i, wrapperCalls[i].data.length));
            chainedWrapperData =
                abi.encodePacked(chainedWrapperData, uint16(wrapperCalls[i].data.length), wrapperCalls[i].data);
        }

        return chainedWrapperData;
    }
}
