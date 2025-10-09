// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity >=0.7.6 <0.9.0;
pragma abicoder v2;

/// @title Gnosis Protocol v2 Authentication Interface
/// @author Gnosis Developers
interface GPv2Authentication {
    /// @dev determines whether the provided address is an authenticated solver.
    /// @param prospectiveSolver the address of prospective solver.
    /// @return true when prospectiveSolver is an authenticated solver, otherwise false.
    function isSolver(address prospectiveSolver) external view returns (bool);
}

interface CowSettlement {
    struct GPv2TradeData {
        uint256 sellTokenIndex;
        uint256 buyTokenIndex;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        uint256 flags;
        uint256 executedAmount;
        bytes signature;
    }
    struct GPv2InteractionData {
        address target;
        uint256 value;
        bytes callData;
    }
    function settle(
        address[] calldata tokens,
        uint256[] calldata clearingPrices,
        GPv2TradeData[] calldata trades,
        GPv2InteractionData[][3] calldata interactions
    ) external;
}

interface ICowWrapper {
    function wrappedSettle(
        bytes calldata settleData,
        bytes calldata wrapperData
    ) external;
}

/**
 * @dev Base contract defining required methods for wrappers of the GPv2Settlement contract for CoW orders
 * A wrapper should:
 * * call the equivalent `settle` on the GPv2Settlement contract (0x9008D19f58AAbD9eD0D60971565AA8510560ab41)
 * * verify that the caller is authorized via the GPv2Authentication contract.
 * A wrapper may also execute, or otherwise put the blockchain in a state that needs to be established prior to settlement.
 * Additionally, it needs to be approved by the GPv2Authentication contract
 */
abstract contract CowWrapper {
    event GasLeft(uint256);

    error NotASolver(address unauthorized);
    error WrapperHasNoSettleTarget(uint256 wrapperDataLength, uint256 requiredWrapperDataLength);
    error InvalidSettleData(bytes invalidSettleData);

    GPv2Authentication public immutable AUTHENTICATOR;

    constructor(GPv2Authentication authenticator_) {
        // retrieve the authentication we are supposed to use from the settlement contract
        AUTHENTICATOR = authenticator_;
    }

    /**
     * @dev Called to initiate a wrapped call against the settlement function. See GPv2Settlement.settle() for more information.
     */
    function wrappedSettle(
        bytes calldata settleData,
        bytes calldata wrapperData
    ) external {
        // Revert if not a valid solver
        if (!AUTHENTICATOR.isSolver(msg.sender)) {
            revert NotASolver(msg.sender);
        }

        // Require additional data for next settlement address
        if (wrapperData.length < 20) {
            revert WrapperHasNoSettleTarget(wrapperData.length, 20);
        }

        // the settle data will always be after the first 4 bytes (selector), up to the computed data end point
        _wrap(settleData, wrapperData);
    }

    /**
     * @dev The logic for the wrapper. During this function, `_internalSettle` should be called. `wrapperData` may be consumed as required for the wrapper's particular requirements
     */
    function _wrap(bytes calldata settleData, bytes calldata wrapperData) internal virtual;

    function _internalSettle(bytes calldata settleData, bytes calldata wrapperData) internal {
        // the next settlement address to call will be the next word of the wrapper data
        address nextSettlement;
        assembly {
            nextSettlement := calldataload(sub(wrapperData.offset, 12))
        }
        wrapperData = wrapperData[20:];
        // Encode the settle call

        if (wrapperData.length == 0) {
            // sanity: make sure we are about to call the `settle` function on the settlement contract
            if (bytes4(settleData[:4]) != CowSettlement.settle.selector) {
                revert InvalidSettleData(settleData);
            }

            // we can now call the settlement contract with the settle data verbatim
            (bool success, bytes memory returnData) =
                nextSettlement.call(settleData);

            if (!success) {
                // Bubble up the revert reason
                assembly {
                    revert(add(returnData, 0x20), mload(returnData))
                }
            }
        }
        else {
            CowWrapper(nextSettlement).wrappedSettle(settleData, wrapperData);
        }
    }
}
