// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.7.6 <0.9.0;
pragma abicoder v2;

import "forge-std/console.sol";

import {GPv2Authentication, ICowWrapper} from "./CowWrapper.sol";

/// @title CoW Wrapper Helpers
/// @notice Helper contract providing validation and encoding utilities for CoW Protocol wrapper chains
/// @dev This contract is not designed to be gas-efficient and is intended for off-chain use only.
contract CowWrapperHelpers {
    /// @notice Thrown when wrapper and wrapper data array lengths don't match
    /// @param wrappersLength The length of the wrappers array
    /// @param individualWrapperDatasLength The length of the wrapper data array
    error InvalidInputLengths(uint256 wrappersLength, uint256 individualWrapperDatasLength);

    /// @notice Thrown when a provided address is not an authenticated wrapper
    /// @param wrapperIndex The index of the invalid wrapper in the array
    /// @param unauthorized The address that is not authenticated as a wrapper
    /// @param authenticatorContract The authentication contract that rejected the wrapper
    error NotAWrapper(uint256 wrapperIndex, address unauthorized, address authenticatorContract);

    /// @notice Thrown when a wrapper's parseWrapperData doesn't fully consume its data
    /// @param wrapperIndex The index of the wrapper that didn't consume all its data
    /// @param remainingWrapperData The data that was not consumed by the wrapper
    error WrapperDataNotFullyConsumed(uint256 wrapperIndex, bytes remainingWrapperData);

    /// @notice Thrown when a wrapper's parseWrapperData reverts, which is assumed to be due to malformed data
    /// @param wrapperIndex The index of the wrapper with malformed data
    /// @param wrapperError The error returned by the wrapper's parseWrapperData
    error WrapperDataMalformed(uint256 wrapperIndex, bytes wrapperError);

    /// @notice Thrown when the settlement contract is authenticated as a solver
    /// @dev The settlement contract should not be a solver to prevent direct settlement calls bypassing wrappers
    /// @param settlementContract The settlement contract address
    /// @param authenticatorContract The authentication contract that authenticated the settlement as a solver
    error SettlementContractShouldNotBeSolver(address settlementContract, address authenticatorContract);

    /// @notice The authentication contract used to verify wrapper contracts
    GPv2Authentication public immutable WRAPPER_AUTHENTICATOR;

    /// @notice The authentication contract used to verify solvers
    GPv2Authentication public immutable SOLVER_AUTHENTICATOR;

    /// @notice Constructs a new CowWrapperHelpers contract
    /// @param wrapperAuthenticator_ The GPv2Authentication contract used to verify wrapper contracts
    /// @param solverAuthenticator_ The GPv2Authentication contract used to verify solvers
    constructor(GPv2Authentication wrapperAuthenticator_, GPv2Authentication solverAuthenticator_) {
        WRAPPER_AUTHENTICATOR = wrapperAuthenticator_;
        SOLVER_AUTHENTICATOR = solverAuthenticator_;
    }

    /// @notice Validates a wrapper chain configuration and builds the properly formatted wrapper data
    /// @dev Performs comprehensive validation of the wrapper chain before encoding:
    ///      1. Verifies array lengths match
    ///      2. Verifies each wrapper is authenticated via WRAPPER_AUTHENTICATOR
    ///      3. Verifies each wrapper's data is valid and fully consumed by calling parseWrapperData
    ///      4. Verifies the settlement contract is not authenticated as a solver
    ///      The returned wrapper data format is: [data0][addr1][data1][addr2][data2]...[settlement]
    ///      where data0 is for the first wrapper, addr1 is the second wrapper address, etc.
    /// @param wrapperAddresses Array of wrapper contract addresses in execution order
    /// @param individualWrapperDatas Array of wrapper-specific data corresponding to each wrapper
    /// @param settlementContract The final settlement contract address to call after all wrappers
    /// @return wrapperData The encoded wrapper data ready to be passed to the first wrapper's wrappedSettle
    function verifyAndBuildWrapperData(address[] calldata wrapperAddresses, bytes[] calldata individualWrapperDatas, address settlementContract) external view returns (bytes memory wrapperData) {
        // Basic Sanity: Input arrays should have correct length
        if (wrapperAddresses.length != individualWrapperDatas.length) {
            revert InvalidInputLengths(wrapperAddresses.length, individualWrapperDatas.length);
        }
        
        for (uint256 i = 0;i < wrapperAddresses.length;i++) {
            // Wrapper must be authorized
            if (!WRAPPER_AUTHENTICATOR.isSolver(wrapperAddresses[i])) {
                revert NotAWrapper(i, wrapperAddresses[i], address(WRAPPER_AUTHENTICATOR));
            }


            // The wrapper data must be parsable and fully consumed
            try ICowWrapper(wrapperAddresses[i]).parseWrapperData(individualWrapperDatas[i]) returns (bytes memory remainingWrapperData) {
                if (remainingWrapperData.length > 0) {
                    revert WrapperDataNotFullyConsumed(i, remainingWrapperData);
                }
            } catch (bytes memory err) {
                revert WrapperDataMalformed(i, err);
            }
        }

        // The Settlement Contract should not be a solver
        if (SOLVER_AUTHENTICATOR.isSolver(settlementContract)) {
            revert SettlementContractShouldNotBeSolver(settlementContract, address(SOLVER_AUTHENTICATOR));
        }

        uint256 totalIndividualWrapperDatasLength = 0;
        for (uint256 i = 0;i < individualWrapperDatas.length;i++) {
            totalIndividualWrapperDatasLength += individualWrapperDatas[i].length;
        }

        if (wrapperAddresses.length > 0) {
            wrapperData = abi.encodePacked(individualWrapperDatas[0]);

            for (uint256 i = 1;i < individualWrapperDatas.length;i++) {
                wrapperData = abi.encodePacked(wrapperData, wrapperAddresses[i], individualWrapperDatas[i]);
            }
        }

        wrapperData = abi.encodePacked(wrapperData, settlementContract);

        return wrapperData;
    }
}
