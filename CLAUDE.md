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
- **CoW Protocol** (`lib/cow`): DEX aggregator settlement contracts and order libraries

## Development Commands

### Build
```bash
forge build
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
- `GPv2OrderHelper.sol`: Utilities for constructing CoW Protocol orders
- `SignerECDSA.sol`: ECDSA signature utilities for tests
- `EmptyWrapper.sol`: Minimal wrapper for testing wrapper chaining

## Important Implementation Details

### Security Considerations

- It is generally assumed that the `solvers` (aka, an address for which `CowAuthentication.isSolver()` returns true) is a trusted actor within the system, and . Only in the case that a solver could steal an entire user's deposit or funds, or steal funds beyond what the user specified as their minimum out/minimum buy amount, assume there is incentive for a solver to provide the best rate possible.

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
- `cow/` → CoW Protocol contracts (`lib/cow/src/contracts`)
- `evc/` → Ethereum Vault Connector (`lib/euler-vault-kit/lib/ethereum-vault-connector/src/`)
- `euler-vault-kit/` → Euler vault implementation
- `openzeppelin/` → OpenZeppelin contracts (via EVC dependency)

