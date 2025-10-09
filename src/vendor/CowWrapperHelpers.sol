// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity >=0.7.6 <0.9.0;
pragma abicoder v2;

import "forge-std/console.sol";

import {GPv2Authentication, ICowWrapper} from "./CowWrapper.sol";

/**
 * A helper contract which provides `view` functions for working with wrappers. 
 * @dev This contract is not designed to be gas-efficient, and is intended for off-chain use only.
 */
contract CowWrapperHelpers {
    error InvalidInputLengths(uint256 wrappersLength, uint256 individualWrapperDatasLength);
    error NotAWrapper(uint256 wrapperIndex, address unauthorized, address authenticatorContract);
    error WrapperDataNotFullyConsumed(uint256 wrapperIndex, bytes remainingWrapperData);
    error WrapperDataMalformed(uint256 wrapperIndex, bytes wrapperError);
    error SettlementContractShouldNotBeSolver(address settlementContract, address authenticatorContract);

    GPv2Authentication public immutable WRAPPER_AUTHENTICATOR;
    GPv2Authentication public immutable SOLVER_AUTHENTICATOR;

    constructor(GPv2Authentication wrapperAuthenticator_, GPv2Authentication solverAuthenticator_) {
        // retrieve the authentication we are supposed to use from the settlement contract
        WRAPPER_AUTHENTICATOR = wrapperAuthenticator_;
        SOLVER_AUTHENTICATOR = solverAuthenticator_;
    }

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

        wrapperData = abi.encodePacked(individualWrapperDatas[0]);

        for (uint256 i = 0;i < individualWrapperDatas.length;i++) {
            wrapperData = abi.encodePacked(wrapperData, wrapperAddresses[i], individualWrapperDatas[i]);
        }

        wrapperData = abi.encodePacked(wrapperData, settlementContract);

        return wrapperData;
    }
}
