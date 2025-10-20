// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.7.6 <0.9.0;
pragma abicoder v2;

/// @title CoW Protocol Authentication Interface
/// @author CoW DAO developers
interface CowAuthentication {
    /// @dev determines whether the provided address is an authenticated solver.
    /// @param prospectiveSolver the address of prospective solver.
    /// @return true when prospectiveSolver is an authenticated solver, otherwise false.
    function isSolver(address prospectiveSolver) external view returns (bool);
}

/// @title CoW Protocol Settlement Interface
/// @notice Minimal interface for CoW Protocol's settlement contract
/// @dev Used for type-safe calls to the settlement contract's settle function
interface CowSettlement {
    /// @notice Trade data structure matching GPv2Settlement
    struct CowTradeData {
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

    /// @notice Interaction data structure for pre/intra/post-settlement hooks
    struct CowInteractionData {
        address target;
        uint256 value;
        bytes callData;
    }

    /// @notice Returns the authentication contract used by the settlement contract.
    function authenticator() external returns (CowAuthentication);

    /// @notice Settles a batch of trades atomically
    /// @param tokens Array of token addresses involved in the settlement
    /// @param clearingPrices Array of clearing prices for each token
    /// @param trades Array of trades to execute
    /// @param interactions Array of three interaction arrays (pre, intra, post-settlement)
    function settle(
        address[] calldata tokens,
        uint256[] calldata clearingPrices,
        CowTradeData[] calldata trades,
        CowInteractionData[][3] calldata interactions
    ) external;
}

/// @title CoW Protocol Wrapper Interface
/// @notice Interface for wrapper contracts that add custom logic around CoW settlements
/// @dev Wrappers can be chained together to compose multiple settlement operations
interface ICowWrapper {
    /// @notice A human readable label for this wrapper. Used for display in explorer/analysis UIs
    function name() external view returns (string memory);

    /// @notice The settlement contract used by this wrapper
    /// @return The CowSettlement contract address
    function SETTLEMENT() external view returns (CowSettlement);

    /// @notice Initiates a wrapped settlement call
    /// @dev This is the entry point for wrapped settlements. The wrapper will execute custom logic
    ///      before calling the next wrapper or settlement contract in the chain.
    /// @param settleData ABI-encoded call to CowSettlement.settle()
    /// @param wrapperData Encoded chain of wrapper-specific data followed by addresses of next wrappers/settlement
    function wrappedSettle(bytes calldata settleData, bytes calldata wrapperData) external;

    /// @notice Parses and validates wrapper-specific data
    /// @dev Used by CowWrapperHelpers to validate wrapper data before execution.
    ///      Implementations should consume their portion of wrapperData and return the rest.
    /// @param wrapperData The wrapper-specific data to parse
    /// @return remainingWrapperData Any wrapper data that was not consumed by this wrapper
    function parseWrapperData(bytes calldata wrapperData) external view returns (bytes calldata remainingWrapperData);
}

/// @title CoW Protocol Wrapper Base Contract
/// @notice Abstract base contract for creating wrapper contracts around CoW Protocol settlements
/// @dev A wrapper enables custom pre/post-settlement and context-setting logic and can be chained with other wrappers.
///      Wrappers must:
///      - Be approved by the CowAuthentication contract
///      - Verify the caller is an authenticated solver
///      - Eventually call settle() on the approved CowSettlement contract
///      - Implement _wrap() for custom logic
///      - Implement parseWrapperData() for validation of implementation-specific wrapperData
abstract contract CowWrapper is ICowWrapper {
    /// @notice Thrown when the caller is not an authenticated solver
    /// @param unauthorized The address that attempted to call wrappedSettle
    error NotASolver(address unauthorized);

    /// @notice Thrown when settle data doesn't contain the correct function selector
    /// @param invalidSettleData The invalid settle data that was provided
    error InvalidSettleData(bytes invalidSettleData);

    /// @notice The settlement contract
    CowSettlement public immutable SETTLEMENT;

    /// @notice The authentication contract used to verify solvers
    /// @dev This is derived from `SETTLEMENT.authenticator()`.
    CowAuthentication public immutable AUTHENTICATOR;

    /// @notice Constructs a new CowWrapper
    /// @param settlement_ The CowSettlement contract to use at the end of the wrapper chain. Also used for wrapper authentication.
    constructor(CowSettlement settlement_) {
        SETTLEMENT = settlement_;
        AUTHENTICATOR = settlement_.authenticator();
    }

    /// @notice Initiates a wrapped settlement call
    /// @dev Entry point for solvers to execute wrapped settlements. Verifies the caller is a solver,
    ///      validates wrapper data, then delegates to _wrap() for custom logic.
    /// @param settleData ABI-encoded call to CowSettlement.settle() containing trade data
    /// @param wrapperData Encoded data for this wrapper and the chain of next wrappers/settlement.
    ///                    Format: [wrapper-specific-data][next-address][remaining-wrapper-data]
    ///                    Must be at least 20 bytes to contain the next settlement target address.
    function wrappedSettle(bytes calldata settleData, bytes calldata wrapperData) external {
        // Revert if not a valid solver
        require(AUTHENTICATOR.isSolver(msg.sender), NotASolver(msg.sender));

        // Delegate to the wrapper's custom logic
        _wrap(settleData, wrapperData);
    }

    /// @notice Parses and validates wrapper-specific data
    /// @dev Must be implemented by concrete wrapper contracts. Used for pre-execution validation.
    ///      The implementation should consume its wrapper-specific data and return the remainder.
    /// @param wrapperData The full wrapper data to parse
    /// @return remainingWrapperData The portion of wrapper data not consumed by this wrapper
    function parseWrapperData(bytes calldata wrapperData) external virtual view returns (bytes calldata remainingWrapperData);

    /// @notice Internal function containing the wrapper's custom logic
    /// @dev Must be implemented by concrete wrapper contracts. Should execute custom logic
    ///      then eventually call _internalSettle() to continue the settlement chain.
    /// @param settleData ABI-encoded call to CowSettlement.settle()
    /// @param wrapperData The wrapper data, which may be parsed and consumed as needed
    function _wrap(bytes calldata settleData, bytes calldata wrapperData) internal virtual;

    /// @notice Continues the settlement chain by calling the next wrapper or settlement contract
    /// @dev Extracts the next target address from wrapperData and either:
    ///      - Calls CowSettlement.settle() directly if no more wrappers remain, or
    ///      - Calls the next CowWrapper.wrappedSettle() to continue the chain
    /// @param settleData ABI-encoded call to CowSettlement.settle()
    /// @param wrapperData Remaining wrapper data starting with the next target address (20 bytes)
    function _internalSettle(bytes calldata settleData, bytes calldata wrapperData) internal {
        if (wrapperData.length == 0) {
            // No more wrapper data - we're calling the final settlement contract
            // Verify the settle data has the correct function selector
            require(bytes4(settleData[:4]) == CowSettlement.settle.selector, InvalidSettleData(settleData));

            // Call the settlement contract directly with the settle data
            (bool success, bytes memory returnData) = address(SETTLEMENT).call(settleData);

            if (!success) {
                // Bubble up the revert reason from the settlement contract
                assembly ("memory-safe") {
                    revert(add(returnData, 0x20), mload(returnData))
                }
            }
        } else {
            // Extract the next wrapper address from the first 20 bytes of wrapperData
            address nextWrapper = address(bytes20(wrapperData[:20]));

            // Skip past the address we just read
            wrapperData = wrapperData[20:];

            // More wrapper data remains - call the next wrapper in the chain
            CowWrapper(nextWrapper).wrappedSettle(settleData, wrapperData);
        }
    }
}
