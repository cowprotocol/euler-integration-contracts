# Euler-CoW Protocol Integration: Wrappers Overview

## Introduction

This repository contains **Euler-CoW Protocol integration contracts** that enable leveraged position management (opening, closing, growing, and shrinking) and collateral swaps through CoW Protocol settlements combined with Ethereum Vault Connector (EVC) operations. The contracts act as "wrappers" that coordinate complex multi-step DeFi operations atomically. Through its
design, further wrappers could be added in the future to satisfy evolving use-cases.

## What Are Wrappers?

Wrappers are smart contracts that add custom logic around [CoW Protocol settlements](https://docs.cow.fi/cow-protocol/reference/contracts/core/settlement). They enable transactions that would otherwise be impossible in a single atomic operation by coordinating multiple steps:

1. **Pre-settlement operations** (e.g., enabling vaults, approving collateral)
2. **CoW Protocol settlement** (DEX aggregation and order matching, converting to Euler vault tokens)
3. **Post-settlement operations** (e.g., repaying debt, adding collateral to user's vault)

All of these steps execute atomically within an EVC batch, allowing for flash-loan like functionality where tokens can be borrowed before the supporting collateral exists.

## Architecture Overview

### Base Framework: CowWrapper

`CowWrapper.sol` is a self-contained abstract base contract provided by the CoW DAO which should be used for all wrappers. In particular it ensures:

- **Solver Authentication**: Verifies that only authenticated CoW Protocol solvers can initiate settlements
- **Wrapper Chaining**: Allows multiple wrappers to be chained together, where each wrapper processes its own logic before delegating to the next wrapper or final settlement
- **Settlement Routing**: Routes the settlement call through the wrapper chain to the CoW Protocol settlement contract

### EVC Integration Base: CowEvcBaseWrapper

`CowEvcBaseWrapper.sol` extends `CowWrapper` with:

- **EVC Batch Coordination**: Manages batching of operations within the EVC's atomic execution context
- **Authorization Mechanisms**: Supports two authorization flows:
  - **EVC Permit Flow**: Users sign a permit message for one-time authorization with the EVC
  - **Pre-Approved Hash Flow**: Users pre-approve operation hashes on-chain (useful for EIP-7702 wallets)
- **Parameter Hashing**: Uses EIP-712 to securely hash parameters and verify user intent
- **Account Health Checks**: Leverages EVC's automatic account status checks at batch conclusion

## The Wrappers

### 1. CowEvcOpenPositionWrapper

**Purpose**: Opens or grows leveraged positions (long or short)

**Flow**:
1. Wrapper validates user authorization (permit or pre-approved hash)
2. Enable collateral vault as collateral
3. Enable borrow vault as controller
4. Deposit user's margin collateral as needed
5. Borrow assets against the collateral
6. Execute CoW settlement to swap borrowed assets → collateral assets
7. All operations occur atomically within EVC batch
8. EVC validates account is sufficiently collateralized (above minimum collateral ratio)

**Result**: User holds a leveraged position with borrowed assets converted to additional collateral

**Example**: User deposits 1000 USDC, borrows 5 ETH (when 1 ETH = $1000), swaps those 5 ETH back to $5000 USDC. Result: 6000 USDC collateral backing $5000 WETH debt (120% collateralization).

### 2. CowEvcClosePositionWrapper

**Purpose**: Closes leveraged positions (full or partial)

**Flow**:
1. Wrapper validates user authorization
2. Create or reuse an Inbox contract (temporary fund holder unique to each Euler subaccount for security)
3. Transfer collateral from subaccount to Inbox
4. Execute CoW settlement to swap collateral → debt repayment assets
5. Repay debt on user's behalf using swapped assets
6. Return excess assets to user's account
7. All operations occur atomically within EVC batch

**Special Considerations**:
- **Unlike other wrappers, uses an `Inbox` contract as the settlement receiver and sender. This means that this wrapper should be signed as a EIP-1271 order.**
- Inbox temporarily holds swapped funds and manages repayment
- Supports both full repayment (with CoW order kind `KIND_BUY`) and partial repayment (`KIND_SELL`)

**Result**: User's debt is repaid and remaining collateral is returned

**Example**: User closes a 5 ETH short position (ETH = $1000). Around 5000 USDC collateral is swapped to exactly the user's debt of 5 ETH. The debt is repaid, and remaining USDC ($1000) is returned to the owner's account.

### 3. CowEvcCollateralSwapWrapper

**Purpose**: Swaps all or a portion of collateral between different Euler vaults while holding debt

**Flow**:
1. Wrapper validates user authorization
2. Enable destination vault as new collateral
3. Transfer collateral from subaccount to main account (if using subaccount)
4. Execute CoW settlement to swap old collateral → new collateral
5. New collateral is automatically deposited in the destination vault
6. All operations occur atomically within EVC batch
7. EVC validates account is sufficiently collateralized after swap (above minimum collateral ratio)

**Result**: User's collateral composition changes without closing the position

**Example**: User swaps from 1000 USDC collateral to 1 WETH collateral while maintaining their debt position.

## How Wrappers Fit Into CoW Orders

Each wrapper is referenced in the CoW order's `appData` along with its encoded parameters:

```json
{
  "appCode": "euler_position_open",
  "wrappers": [
    {
      "address": "<wrapper-contract-address>",
      "data": "<abi-encoded-params><signature-if-needed>"
    }
  ]
}
```

Where `<wrapper-contract-address>` is the address of whichever user operation is occuring (ex. open position, close position, collateral swap), `<abi-encoded-params>` should be the parameters object being used by the current wrapper, and `<signature-if-needed>` is the EVC permit signature if using the permit authorization flow.

The solver executes the wrapper instead of the settlement contract directly, which results in the requested user operation being handled.

## Authorization Flows

There are two different ways a user can authorize their order.

### Flow 1: EVC Permit (Off-Chain Signature)

Users provide a [EIP-712 EVC.permit signature](https://evc.wtf/docs/concepts/internals/permit/) of the data returned by `getPermitData(params)` authorizing a specific operation.

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

**Advantages**: Requires less (potentially no) on-chain transactions, no need to set trust to the wrapper contract as an operator
**Disadvantages**: Not compatible with smart contract wallets, impossible to reduce to one signature request from the user

### Flow 2: Pre-Approved Hash (On-Chain)

Users pre-approve operation hashes on-chain:

1. User's browser creates the `params` for the wrapper and the trade they want to execute
2. If any approvals are required for the trade to succeed, the user needs to sign an on-chain transaction for these (see the specific section for the wrapper being executed),
2. User's browser receives operation hash by calling the wrapper: `wrapper.getApprovalHash(params)`
3. User executes on-chain transaction `wrapper.setPreApprovedHash(hash, true)`
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

- **Euler Vault Kit** (`lib/euler-vault-kit`): ERC4626 vault implementation with borrowing support
- **Ethereum Vault Connector (EVC)**: Batch transaction coordinator with account health checks
- **CoW Protocol** (`lib/cow`): DEX aggregator settlement contracts and order libraries
- **OpenZeppelin**: Standard token interfaces (via EVC dependency)

## Related Documentation

- [Ethereum Vault Connector](https://evc.wtf/) - Batch execution and account management
- [CoW Protocol](https://docs.cow.fi/) - Intent-based DEX aggregation
- [Euler Vaults](https://docs.euler.finance/concepts/core/vaults/) - Vault mechanics
- [EIP-4626](https://eips.ethereum.org/EIPS/eip-4626) - Tokenized vault standard
- [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) - Set code for account transactions
