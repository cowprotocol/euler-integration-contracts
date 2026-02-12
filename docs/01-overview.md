# Euler-CoW Protocol Integration: Wrappers Overview

## Introduction

This repository contains **Euler-CoW Protocol integration contracts** that enable leveraged position management (opening, closing, growing, and shrinking) and collateral swaps through CoW Protocol settlements combined with [Ethereum Vault Connector (EVC)](https://evc.wtf/) operations. The contracts, using CoW's [Generalized Wrappers](https://docs.cow.fi/cow-protocol/concepts/order-types/wrappers) architecture, coordinate complex multi-step DeFi operations atomically around a CoW settlement operation. Through its
design, further wrappers could be added in the future to satisfy evolving use-cases.

## What is the EVC?

Short for Ethereum Vault Connector, its an architecture designed and used by the [Euler Finance](https://eulerlabs.com/) team to coordinate money market operations between [vault contracts](https://docs.euler.finance/concepts/core/vaults/).

## What Are Wrappers?

Wrappers are smart contracts that add custom logic around [CoW Protocol settlements](https://docs.cow.fi/cow-protocol/reference/contracts/core/settlement). They serve as the basis for the implementation of the Euler integration with CoW.

## Architecture Overview

### Base Framework: CowWrapper

[`CowWrapper.sol`](../../src/CowWrapper.sol) is a self-contained abstract base contract provided by the CoW DAO which should be used for all wrappers. In particular it ensures:

- **Solver Authentication**: Verifies that only authenticated CoW Protocol solvers can initiate settlements
- **Wrapper Chaining**: Allows multiple wrappers to be chained together, where each wrapper processes its own logic before delegating to the next wrapper or final settlement
- **Settlement Routing**: Routes the settlement call through the wrapper chain to the CoW Protocol settlement contract

### EVC Integration Base: CowEvcBaseWrapper

[`CowEvcBaseWrapper.sol`](../../src/CowEvcBaseWrapper.sol) extends `CowWrapper` with:

- **EVC Batch Coordination**: Manages batching of operations within the [EVC's atomic execution context](https://evc.wtf/docs/concepts/internals/batch)
- **Authorization Mechanisms**: Supports two authorization flows:
  - **EVC Permit Flow**: Users sign a [permit message](https://evc.wtf/docs/concepts/internals/permit/) for one-time authorization with the EVC
  - **Pre-Approved Hash Flow**: Users pre-approve operation hashes on-chain (useful for EIP-7702 wallets)
- **Parameter Hashing**: Uses EIP-712 to securely hash parameters and verify user intent
- **Account Health Checks**: Leverages EVC's automatic account status checks at batch conclusion

## The Wrappers

### 1. CowEvcOpenPositionWrapper

The [`CowEvcOpenPositionWrapper`](../../src/CowEvcOpenPositionWrapper.sol) opens or grows leveraged positions (long or short).

**Example**: The user starts with no funds or debt in their account. User deposits 1000 USDC, borrows 5 ETH (when 1 ETH = $1000), swaps those 5 ETH back to $5000 USDC. Result: 6000 USDC collateral backing $5000 WETH debt (120% collateralization).

**Result**: User holds a leveraged position with borrowed assets converted to additional collateral

See the [dedicated page](./02-open-position.md) on this wrapper.

### 2. CowEvcClosePositionWrapper

The [`CowEvcClosePositionWrapper`](../../src/CowEvcClosePositionWrapper.sol) closes leveraged positions (full or partial)

**Example**: Using the position opened in the open position wrapper above as an example, the user closes all 5 ETH of their short position (ETH = $1000). Around 5000 USDC collateral is swapped to exactly the user's debt of 5 ETH. The debt is repaid, and remaining USDC ($1000) is left in the account.

**Result**: User's debt is repaid and remaining collateral is left in the account

See the [dedicated page](./03-close-position.md) on this wrapper.

### 3. CowEvcCollateralSwapWrapper

The [`CowEvcCollateralSwapWrapper`](../../src/CowEvcCollateralSwapWrapper.sol) swaps all or a portion of collateral between different Euler vaults while holding debt

**Example**: Using the position opened in the open position wrapper above as an example, the user swaps their full 6000 USDC collateral to ~0.06 BTC (1 BTC = $100000) collateral while maintaining their debt position.

**Result**: The user holds both 0.06 BTC as collateral assets against their ETH debt. User's collateral composition changes without closing the position

See the [dedicated page](./04-collateral-swap.md) on this wrapper.

## Authorization Flows

There are two different ways a user can authorize their order.

### Flow 1: EVC Permit (Off-Chain Signature)

Users provide an EIP-712 EVC.permit signature of the data returned by `getPermitData(params)` authorizing a specific operation.

Additionally, the user signs a [EIP-712 order with CoW](https://docs.cow.fi/cow-protocol/reference/core/signing-schemes#eip-712) (in the case of the close position wrapper, its a EIP-1271 order with the same signing).

The full flow is:

1. User's browser creates the `params` for the wrapper and the trade they want to execute
2. If any approvals are required for the trade to succeed, the user needs to sign an on-chain transaction for these (see the specific section for the wrapper being executed),
3. User's browser calls `getPermitData()` view function on the wrapper to get the `data` field that needs to be signed for the given params.
4. User's signer signs 
5. User's browser generates the corresponding CoW order to `params`
6. User's signer signs the CoW order
7. User's browser constructs a wrapper request with the CoW order + signature, and then submits to the CoW API.
8. When a solver executes the order, the wrapper validates signature via `EVC.permit()`

**Advantages**: Requires less (potentially no) on-chain transactions, no need to set trust to the wrapper contract as an [operator](https://evc.wtf/docs/concepts/internals/operators)
**Disadvantages**: Not compatible with smart contract wallets, impossible to reduce to one signature request from the user

### Flow 2: Pre-Approved Hash (On-Chain)

Users pre-approve operation hashes on-chain:

1. User's browser creates the `params` for the wrapper and the trade they want to execute
2. If any approvals are required for the trade to succeed, the user needs to sign an on-chain transaction for these (see the specific section for the wrapper being executed),
3. User's browser receives operation hash by calling the wrapper: `wrapper.getApprovalHash(params)`
4. User executes on-chain transaction `wrapper.setPreApprovedHash(hash, true)`
5. User's browser generates the corresponding CoW order to `params`
6. User executes on-chain transaction to the CoW settlement contract `settlement.setPreSignature(orderUid, true)`
7. Later, wrapper validates hash was pre-approved in contract storage
8. Hash is permanently consumed after use, cannot be replayed

**Advantages**: With [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) wallets and wallet batching through [`wallet_sendCalls`](https://docs.metamask.io/wallet/reference/json-rpc-methods/wallet_sendcalls), can batch all needed approvals. Can be gassless with [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337). Works seamlessly with smart contract wallets.
**Disadvantages**: If the wallet is not capable of batching transactions, requires at least 3 extra on-chain transactions.

## Security Model

### Trusted Actor: Solvers

The system assumes solvers are generally trusted to provide good execution prices, as they are subject to slashing for misbehavior. There are various onchain safeguards providing concrete protection:

- **Clearing Price Validation**: User-signed limit prices in the CoW order prevent solvers from setting arbitrary clearing prices below user specified limits
- **Signature Verification**: User authorization (permit or pre-approved hash) proves user intent
- **Account Health Enforcement**: EVC enforces minimum collateralization at batch end, preventing undercollateralized positions

### Threat Model

**What solvers CANNOT do:**
- Steal user funds by setting arbitrary clearing prices (limit price validation prevents this)
- Alter user-signed operation parameters (signature would be invalid)
- Extract value beyond slashing bond amount (due to off-chain auction dynamics)

**Potential risks/what solvers CAN do (but is slashed):**
- Execute the CoW order without the corresponding wrapper call
- Execute the Wrapper without the corresponding CoW order
- Skim off execess funds 

A detailed accounting of these risks and more can be seen in the [security considerations](./05-security-considerations.md) section.

## Key Dependencies

- **[Ethereum Vault Connector (EVC)](https://evc.wtf/)**: Batch transaction coordinator with account health checks
- **CoW Protocol** (`lib/cow`): DEX aggregator settlement contracts and order libraries
- **Euler Vault Kit** (`lib/euler-vault-kit`): ERC4626 vault implementation with borrowing support
- **OpenZeppelin**: Standard token interfaces (via EVC dependency)

## Related Documentation

- [Ethereum Vault Connector](https://evc.wtf/) - Batch execution and account management
- [CoW Protocol](https://docs.cow.fi/) - Intent-based DEX aggregation
- [Euler Vaults](https://docs.euler.finance/concepts/core/vaults/) - Vault mechanics
- [EIP-4626](https://eips.ethereum.org/EIPS/eip-4626) - Tokenized vault standard
- [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) - Set code for account transactions
