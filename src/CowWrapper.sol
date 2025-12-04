// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title CoW Wrapper all-in-one integration file
 * @author CoW Protocol Developers
 * @notice This file is completely self-contained (ie no dependencies) and can be portably copied to whatever projects it is needed.
 * It contains:
 * * CowWrapper -- an abstract base contract which should be inherited by all wrappers
 * * ICowWrapper -- the required interface for all wrappers
 * * ICowSettlement -- A minimized interface and base structures for CoW Protocol settlement contract. From https://github.com/cowprotocol/contracts/blob/main/src/contracts/GPv2Settlement.sol
 * * ICowAuthentication -- The authentication interface used by ICowSettlement. From https://github.com/cowprotocol/contracts/blob/main/src/contracts/interfaces/GPv2Authentication.sol
 */

/// @title CoW Protocol Authentication Interface
/// @author CoW DAO developers
interface ICowAuthentication {
    /// @dev determines whether the provided address is an authenticated solver.
    /// @param prospectiveSolver the address of prospective solver.
    /// @return true when prospectiveSolver is an authenticated solver, otherwise false.
    function isSolver(address prospectiveSolver) external view returns (bool);
}

/// @title CoW Protocol Settlement Interface
/// @notice Minimal interface for CoW Protocol's settlement contract
/// @dev Used for type-safe calls to the settlement contract's settle function
interface ICowSettlement {
    /// @notice Trade data structure matching GPv2Settlement
    struct Trade {
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

    /// @notice Interaction data structure for pre/intra/post-settlement actions which are supplied by the solver to complete the user request
    struct Interaction {
        address target;
        uint256 value;
        bytes callData;
    }

    /// @notice Returns the authentication contract used by the settlement contract.
    function authenticator() external view returns (ICowAuthentication);

    /// @notice Returns the address of the vaultRelayer, the target for approvals for funds entering the settlement contract.
    function vaultRelayer() external view returns (address);

    /// @notice Returns the domain separator for EIP-712 signing
    function domainSeparator() external view returns (bytes32);

    /// @notice Allows for approval of orders by submitting an authorized hash on-chain prior to order execution.
    function setPreSignature(bytes calldata orderUid, bool signed) external;

    /// @notice Settles a batch of trades atomically
    /// @param tokens Array of token addresses involved in the settlement
    /// @param clearingPrices Array of clearing prices for each token
    /// @param trades Array of trades to execute
    /// @param interactions Array of three interaction arrays (pre, intra, post-settlement)
    function settle(
        address[] calldata tokens,
        uint256[] calldata clearingPrices,
        Trade[] calldata trades,
        Interaction[][3] calldata interactions
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
    function SETTLEMENT() external view returns (ICowSettlement);

    /// @notice Initiates a wrapped settlement call
    /// @dev This is the entry point for wrapped settlements. The wrapper will execute custom logic
    ///      before calling the next wrapper or settlement contract in the chain.
    /// @param settleData ABI-encoded call to ICowSettlement.settle() containing trade data
    /// @param chainedWrapperData Encoded data for this wrapper and the chain of next wrappers/settlement.
    ///                    Format: [2-byte len][wrapper-specific-data][next-address]([2-byte len][wrapper-specific-data][next-address]...)
    function wrappedSettle(bytes calldata settleData, bytes calldata chainedWrapperData) external;

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
///      - Be approved by the ICowAuthentication contract
///      - Verify the caller is an authenticated solver
///      - Eventually call settle() on the approved ICowSettlement contract
///      - Implement _wrap() for custom logic
abstract contract CowWrapper is ICowWrapper {
    /// @notice Thrown when the caller is not an authenticated solver
    /// @param unauthorized The address that attempted to call wrappedSettle
    error NotASolver(address unauthorized);

    /// @notice Thrown when settle data doesn't contain the correct function selector
    /// @param invalidSettleData The invalid settle data that was provided
    error InvalidSettleData(bytes invalidSettleData);

    /// @notice The settlement contract
    ICowSettlement public immutable SETTLEMENT;

    /// @notice The authentication contract used to verify solvers
    /// @dev This is derived from `SETTLEMENT.authenticator()`.
    ICowAuthentication public immutable AUTHENTICATOR;

    /// @notice Constructs a new CowWrapper
    /// @param settlement_ The ICowSettlement contract to use at the end of the wrapper chain. Also used for wrapper authentication.
    constructor(ICowSettlement settlement_) {
        SETTLEMENT = settlement_;
        AUTHENTICATOR = settlement_.authenticator();
    }

    /// @inheritdoc ICowWrapper
    function wrappedSettle(bytes calldata settleData, bytes calldata chainedWrapperData) external {
        // Revert if not a valid solver
        require(AUTHENTICATOR.isSolver(msg.sender), NotASolver(msg.sender));

        // Find out how long the next wrapper data is supposed to be
        // We use 2 bytes to decode the length of the wrapper data because it allows for up to 64KB of data for each wrapper.
        // This should be plenty of length for all identified use-cases of wrappers in the forseeable future.
        uint16 nextWrapperDataLen = uint16(bytes2(chainedWrapperData[0:2]));

        // Delegate to the wrapper's custom logic
        uint256 remainingWrapperDataStart = 2 + nextWrapperDataLen;
        _wrap(settleData, chainedWrapperData[2:remainingWrapperDataStart], chainedWrapperData[remainingWrapperDataStart:]);
    }

    /// @inheritdoc ICowWrapper
    function parseWrapperData(bytes calldata wrapperData)
        external
        view
        virtual
        returns (bytes calldata remainingWrapperData);

    /// @notice Internal function containing the wrapper's custom logic
    /// @dev Must be implemented by concrete wrapper contracts. Should execute custom logic
    ///      then eventually call _next() to continue the wrapped settlement chain.
    /// @param settleData ABI-encoded call to ICowSettlement.settle()
    /// @param wrapperData The wrapper data which should be consumed by this wrapper
    /// @param remainingWrapperData The reminder bytes resulting from consuming the current's wrapper data from the original `chainedWrapperData` in the `wrappedSettle` call. This should be passed unaltered to `_next` that will call the settlement function if this remainder is empty, or delegate the settlement to the next wrapper
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        virtual;

    /// @notice Continues the wrapped settlement chain by calling the next wrapper or settlement contract
    /// @dev Extracts the next target address from wrapperData and either:
    ///      - Calls ICowSettlement.settle() directly if no more wrappers remain, or
    ///      - Calls the next CowWrapper.wrappedSettle() to continue the chain
    /// @param settleData ABI-encoded call to ICowSettlement.settle()
    /// @param remainingWrapperData Remaining wrapper data starting with the next target address (20 bytes)
    function _next(bytes calldata settleData, bytes calldata remainingWrapperData) internal {
        if (remainingWrapperData.length == 0) {
            // No more wrapper data - we're calling the final settlement contract
            // Verify the settle data has the correct function selector
            require(bytes4(settleData[:4]) == ICowSettlement.settle.selector, InvalidSettleData(settleData));

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
            address nextWrapper = address(bytes20(remainingWrapperData[:20]));

            // Skip past the address we just read
            remainingWrapperData = remainingWrapperData[20:];

            // More wrapper data remains - call the next wrapper in the chain
            CowWrapper(nextWrapper).wrappedSettle(settleData, remainingWrapperData);
        }
    }
}
