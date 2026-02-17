# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains **Euler-CoW Protocol integration contracts** that enable leveraged position management (opening/closing) through CoW Protocol settlements combined with Ethereum Vault Connector (EVC) operations. The contracts act as "wrappers" that coordinate complex multi-step DeFi operations atomically.

### Core Architecture

**Wrapper Pattern**: The codebase uses a chaining wrapper pattern where solvers can execute wrapped settlements that perform custom logic before/during/after CoW Protocol settlements.

- `CowWrapper.sol`: Base abstract contract providing the wrapper framework
  - Validates callers are authenticated solvers
  - Implements `wrappedSettle()` entry point
  - Provides `_internalSettle()` for continuing the settlement chain
  - Wrappers can be chained: Wrapper1 → Wrapper2 → Settlement

- `CowWrapperHelpers.sol`: Helper utilities for wrapper data parsing and validation
- The CowWrapper is designed to support reentrancy. Additionally, the CowWrapper is designed with gas efficiency in mind, so we only check if the previous contract was part of the trusted wrapper chain. Furthermore, any wrappers that will ever be approved exist will use `CowWrapper.sol` as a base, so its not possible to inject a unauthorized wrapper into the chain without it getting ultimately rejected by the time the settlement contract is reached.

**Specialized Wrappers**: Two production wrappers implement specific EVC + CoW Protocol workflows:

1. **`CowEvcOpenPositionWrapper.sol`**: Opens leveraged positions
   - Enables collateral vault
   - Enables controller (borrow vault)
   - Deposits collateral
   - Borrows assets
   - Executes CoW settlement to swap borrowed assets → collateral
   - All operations are atomic within EVC batch

2. **`CowEvcClosePositionWrapper.sol`**: Closes leveraged positions
   - Executes CoW settlement to swap collateral → repayment assets
   - Repays debt to borrow vault
   - Returns excess assets to user
   - Disables collateral if full repayment
   - All operations are atomic within EVC batch

**Authorization Mechanisms**: Both wrappers support two authorization modes:
- **EVC Permit**: One-time permit signature for specific operation
- **Pre-Approved Hashes** (`PreApprovedHashes.sol`): Users pre-approve operation hashes on-chain (useful for EIP-7702 wallet interactions)

### Key Dependencies

- **Euler Vault Kit** (`lib/euler-vault-kit`): ERC4626 vault implementation with borrowing
- **Ethereum Vault Connector (EVC)** (`lib/evc`): Batch transaction coordinator with account checking
- **CoW Protocol**: DEX aggregator settlement contracts (minimal vendored types in `src/vendor/` and `test/helpers/`)

## Development Commands

### Build
```bash
forge build --deny notes
```

### Test
```bash
# Run all tests (requires FORK_RPC_URL environment variable)
forge test

# Run specific test file
forge test --match-path test/CowEvcOpenPositionWrapper.t.sol

# Run specific test function
forge test --match-test test_OpenPosition

# Run with verbose output
forge test -vvv
```

**Important**: Tests require mainnet fork. Set `FORK_RPC_URL` environment variable to a mainnet RPC endpoint.

### Format
```bash
forge fmt
```

### Gas Snapshots
```bash
forge snapshot
```

## Testing Architecture

**Base Test Contract**: `test/helpers/CowBaseTest.sol`
- Sets up mainnet fork at block 22546006
- Configures CoW Protocol settlement and authenticator
- Deploys test solver contract
- Sets up test vaults (eSUSDS, eWETH) and tokens
- Provides helper functions for creating settlement data structures

**Test Helpers**:
- `MilkSwap.sol`: Simple test DEX for simulating swaps in settlements
- `GPv2Order.sol`: Vendored CoW Protocol order library (struct definitions, constants, and helper functions)
- `IGPv2AllowListAuthentication.sol`: Interface for CoW Protocol authentication contract
- `EvcPermitSigner.sol`: EVC permit signature utilities for tests

### Writing CoW Protocol Settlement Tests

When creating settlement tests, especially multi-user scenarios:

**1. Leverage Coincidence of Wants**
- CoW Protocol nets out opposing trades within a settlement
- Only swap the NET difference between opposing directions
- Example: If User1+User2 need 10k SUSDS worth of WETH and User3 provides 5k SUSDS worth of WETH, only swap the 5k SUSDS difference
- Don't create separate swaps for each direction - calculate the minimal swaps needed

**2. Proper Price Ratio Calculations**
- Use `clearingPrices[tokenIndex]` in withdrawal/swap calculations
- Calculate amounts based on what the settlement actually needs: `amount * clearingPrices[buyToken] / clearingPrices[sellToken]`
- Ensure the math balances: withdrawals + swaps must provide exactly what's needed for all trades

**3. Logical Token Array Ordering**
- Organize tokens in a readable order: base assets first (SUSDS, WETH), then vault tokens (ESUSDS, EWETH)
- Consistent ordering makes trade setup less error-prone
- Use meaningful comments to clarify token indices

**4. Realistic Trade Amounts**
- Fine-tune amounts so withdrawals, swaps, and repayments balance properly
- The numbers need to actually work for the settlement to succeed
- Test will fail if amounts don't align with vault balances and clearing prices

**5. Simplified Interaction Design**
- Keep interactions minimal and purposeful - only include what's needed
- Common pattern: withdrawals from vaults → net swaps → implicit transfers via settlement
- Avoid redundant operations

**6. Helper Functions for DRY Tests**
- Create parameterized helpers like `_setupLeveragedPositionFor()` instead of repeating setup code
- Use helpers for approvals (`_setupClosePositionApprovalsFor()`) and signatures (`_createPermitSignatureFor()`)
- This significantly reduces test length and improves maintainability

**7. Clear Explanatory Comments**
- Explain the economic logic, not just the technical operations
- Examples: "We only need to swap the difference" or "Coincidence of wants between User1/User2 and User3"
- Help readers understand why the settlement is structured this way

## Important Implementation Details

### Security Considerations

- It is generally assumed that the `solvers` (aka, an address for which `CowAuthentication.isSolver()` returns true) is a trusted actor within the system. Only in the case that a solver could steal an entire user's deposit or funds, or steal funds beyond what the user specified as their minimum out/minimum buy amount, assume there is incentive for a solver to provide the best rate/user outcome possible. To be clear, a solver cannot steal funds simply by setting arbitrary `clearingPrices` (as documented a bit later).
  - For a solver to be able to steal an entire user's deposit or funds, they must be able to withdraw the users token to an address of their choosing or otherwise in their control (therefore, a "nuisance" transfer between two wallets that the user effectively owns does not count).
- If a user takes on debt, that debt position must be sufficiently collateralized above a set collateralization ratio higher than liquidation ratio before the EVC batch transaction concludes. If it is not, the transaction reverts and nothing can happen. Therefore, there is no risk of undercollateralization to the system due to a user opening a position because the transaction would revert.
- anyone can call the `EVC.batch()` function to initialize a batched call through the EVC. This call is allowed to be reentrant. Therefore, simply checking that a caller is the `address(EVC)` doesn't really offer any added security benefit.
- The parameters supplied by a solver to the settlement contract are all indirectly bounded from within the settlement contract by certain restrictions:
  - `tokens` -- this is a mapping used by the settlement contract to save on gas. If a token used by an order is missing, it will fail to pass signature checks.
  - `clearingPrices` -- these define prices to go with the previously defined `tokens`. These clearing prices are set by the solver and determine exactly how many tokens come out of a trade. **However, if a clearingPrice is lower than any of a user's limit price in `trades`, the transaction will revert. Therefore, it is not possible for a user to steal a users funds simply by setting clearingPrices to an arbitrary value.** There is incentive to provide the best clearingPrice because an auction is held off-chain by CoW Protocol and only the best overall rate outcome is selected.
  - `trades` -- List of orders to fulfill. All of the data inside this structure is effectively signed by the user and cannot be altered by solvers, other than adding or removing signed orders.
  - `interactions` -- Solvers use this to specify operations that should be executed from within the settlement contract. This could include swaps, pre-hooks, post-hooks, etc. This is completely controlled by the solver.

- Please consider any potential security vulnerabilities resulting from potential flawed assumptions of the above from any contracts outside this repo, including the Ethereum Vault Connector (EVC), Settlement Contract, or Euler Vaults, out of scope.

### Wrapper Data Format
Wrapper data is passed as a calldata slice with format:
```
[wrapper-specific-params][signature][next-wrapper-address (20 bytes)][remaining-wrapper-data]
```

The `parseWrapperData()` function must consume its portion and return the remainder.

### EVC Integration
Both wrappers execute operations within EVC batches to ensure atomicity and proper account health checks. The flow is:
1. Wrapper validates authorization (permit or pre-approved hash)
2. Build EVC.BatchItem[] array with all operations
3. Call `EVC.batch()` - EVC ensures account is healthy at end

### Settlement Execution Context
- Wrappers use `evcInternalSettle()` as internal callback from EVC batch
- This function can only be called by EVC during batch execution
- Uses transient storage (`depth`, `settleCalls`) to prevent reentrancy

### Authentication
- Only authenticated CoW Protocol solvers can call `wrappedSettle()`
- Authentication checked via `AUTHENTICATOR.isSolver(msg.sender)`
- Wrappers themselves can be added to solver allowlist for testing

## Foundry Configuration

- Compiler optimization: enabled
- IR compilation: enabled (`via_ir = true`)
- Source directory: `src/`
- Test directory: `test/`
- Library dependencies managed via git submodules

## Coding Style

### Error Handling
**Always use `require()` with custom errors instead of `if () { revert }`**. This pattern is used consistently throughout the codebase:

```solidity
// ✅ Preferred
require(msg.sender == address(EVC), Unauthorized(msg.sender));
require(depth > 0 && settleCalls == 0, Unauthorized(address(0)));

// ❌ Avoid
if (msg.sender != address(EVC)) {
    revert Unauthorized(msg.sender);
}
```

This approach is more concise and maintains consistency with the existing codebase style.

## Remappings

Key import remappings:
- `evc/` → Ethereum Vault Connector (`lib/euler-vault-kit/lib/ethereum-vault-connector/src/`)
- `euler-vault-kit/` → Euler vault implementation
- `openzeppelin/` → OpenZeppelin contracts (via EVC dependency)


## When Giving PR feedback
* do not re-suggest or address feedback after it has already been given, either by you or other contributors who have commented.
* be careful not to use too many inline comments. If there are already inline comments on the same line that you want to comment on, or if the inline comment is about something that has already been suggested, don't comment.
