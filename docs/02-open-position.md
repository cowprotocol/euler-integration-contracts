# Opening Leveraged Positions with CowEvcOpenPositionWrapper

## Overview

The `CowEvcOpenPositionWrapper` enables users to atomically open or grow leveraged trading positions by:

1. Depositing collateral into a vault
2. Borrowing assets against that collateral
3. Swapping borrowed assets back into collateral via CoW Protocol
4. All within a single atomic EVC batch

This pattern allows leveraged long/short positions with optimal execution through CoW's distributed solver network.

![Open Position Flow](./images/open-position-diagram.png)

## Use Cases

Assuming 1 ETH = 1000 USDC

### Leveraged Long Position
User wants to go 5x long on ETH:
- Deposit 1 ETH as collateral
- Borrow 4000 USDC
- Swap borrowed USDC → ETH collateral
- Result: 5 ETH collateral backing 4000 USDC debt

### Leveraged Short Position
User wants to go 5x short on ETH:
- Deposit 1000 USDC as collateral
- Borrow 5 ETH
- Swap borrowed ETH → USDC collateral
- Result: 6000 USDC collateral backing 5 ETH debt

### Growing Existing Position
User can execute another open position operation to increase leverage on an existing position.

## Parameters

### OpenPositionParams Structure

```solidity
struct OpenPositionParams {
    address owner;              // User who authorizes and owns the position
    address account;            // EVC subaccount (can equal owner for default account)
    uint256 deadline;           // Operation deadline (block.timestamp must be ≤ this)
    address collateralVault;    // Vault to hold collateral (e.g., eUSDC)
    address borrowVault;        // Vault to borrow from (e.g., eWETH)
    uint256 collateralAmount;   // Amount of collateral to deposit initially
    uint256 borrowAmount;       // Amount to borrow (in underlying asset)
}
```

#### Parameter Details

- **owner**: The user's address that will own and authorize the position. The CoW order must be signed/authorized by this address.
- **account**: Can be the same as `owner` (default account) or a different subaccount. EVC subaccounts must share the same 19 high-order bits as the owner.
- **deadline**: Used for operation validity and hash uniqueness. If executing multiple operations with identical other parameters, increment deadline for uniqueness.
- **collateralVault**: The vault token address to use as collateral backing (e.g., `eUSDC`)
- **borrowVault**: The vault to borrow from (e.g., `eWETH`). Note: You borrow the underlying asset (WETH), not the vault token
- **collateralAmount**: Amount of underlying collateral asset to deposit. Set to 0 if vault already has margin collateral. This is NOT the same as CoW order `buyAmount`.
- **borrowAmount**: Amount of underlying asset to borrow. This MUST match the CoW order `sellAmount`.

## CoW Order Construction

### Order Parameters

```json
{
  "sellToken": "0x...",           // underlying asset of borrowVault (e.g., WETH)
  "buyToken": "0x...",            // collateralVault (e.g., eUSDC)
  "sellAmount": 5000000000000000000,     // == borrowAmount (5 WETH with 18 decimals)
  "buyAmount": 5000000000000000000,      // Amount of collateral expected back, minus slippage and fees
  "receiver": "0x...",            // == account parameter (the subaccount)
  "kind": "sell",                 // Always "sell" to ensure borrowed amount is fully converted
  "validTo": 1234567890           // Ideally same as deadline parameter
}
```

## Authorization Flows

### Option 1: EVC Permit (Off-Chain Signature)

```solidity
// User generates approval hash
bytes32 hash = openPositionWrapper.getApprovalHash(params);

// User signs permit for EVC (off-chain)
// This requires 2 signatures total:
// 1. EVC permit signature
// 2. CoW order signature
// Plus potentially 1 on-chain approval if first-time margin deposit

bytes memory permitSignature = /* sign EVC permit with wrapper params */;

// When submitting to solver:
// Include permitSignature in wrapper data
bytes wrapperData = abi.encode(params, permitSignature);
```

**On-chain transactions if needed**:
```solidity
// Only if depositing new margin (collateralAmount > 0)
IERC20(collateralVault.asset()).approve(collateralVault, type(uint256).max);
```

### Option 2: Pre-Approved Hash (On-Chain, EIP-7702 Compatible)

```solidity
// User pre-approves the operation (can batch this with other approvals)
bytes32 hash = openPositionWrapper.getApprovalHash(params);
openPositionWrapper.setPreApprovedHash(hash, true);

// User pre-approves the CoW order
cowSettlement.setPreSignature(orderUid, true);

// Only if first-time margin deposit
IERC20(collateralVault.asset()).approve(collateralVault, type(uint256).max);

// Later, wrapper can be called without signature:
// wrapperData = abi.encode(params, new bytes(0)); // Empty signature
```

**Advantages**: Can batch multiple operations, no off-chain signature needed
**Disadvantages**: Requires prior on-chain transactions

## Transaction Flow

### Step-by-Step Execution

1. **Solver validates authorization**: Checks if caller is authenticated solver
2. **Wrapper validates user authorization**: Verifies permit signature or pre-approved hash
3. **EVC batch assembly**: Wrapper constructs EVC batch items:
   - Optional: EVC.permit() if using permit flow
   - Optional: Enable collateral vault (if first time with this vault)
   - Optional: Enable borrow vault (if first time with this vault)
   - Optional: Approve token transfer if collateralAmount > 0
   - Deposit collateral (if collateralAmount > 0)
   - Borrow the required amount
   - **Settlement callback**: Call settlement to execute CoW swap
4. **Settlement execution**: The solver will perform swaps that functionally:
   - Swaps the borrow asset into the collateral asset
   - Converts the collateral asset into vault tokens using `vault.deposit()`
5. **EVC account health check**: Verifies user account is properly collateralized
6. **Batch completion**: If all steps succeed, position is opened

### Memory Layout

Collateral and borrowed asset flows:

```
User's Collateral Asset      User's Borrowed Asset
        |                             |
        v                             v
   Collateral Vault            Borrow Vault
        |                             |
        |                    (Wrapper Borrows)
        |                             |
        |                             v
        |                      Settlement Contract
        |                             |
        |               (CoW Swap: Borrowed -> Collateral)
        |                             |
        +<-----------+----------------+
                     |
                     v
              Collateral Vault (now both initial collateral and borrowed asset)
                     |
                     v
              EVC Subaccount (user's account)
```

## Important Considerations

### Collateral Requirements

Positions must maintain above the **minimum collateral ratio** for the vault pair:
- If collateral ratio falls below minimum, the position will be liquidated
- The EVC automatically enforces this at batch conclusion
- Example: If minimum is 110%, a 5x position needs 1/(5-1) = 25% surplus (6000/5000 = 120%)

Additionally, each borrow vault maintains a list of *authorized* collateral vaults. If the collateral vault is not authorized,
the EVC check will fail.

### Price Impact and Slippage

- **buyAmount in CoW order**: Set to the minimum acceptable collateral expected. Reccomended to use [Cow SDK](https://docs.cow.fi/cow-protocol/reference/sdks/cow-sdk) for help in computing.
- If the swap produces less collateral than buyAmount, the transaction reverts
- CoW off-chain solver auction ensures competitive pricing
- No slippage protection needed beyond this (atomic within batch)

### Deadline Handling

- **deadline parameter**: Block timestamp must be ≤ deadline or operation reverts
- Typically set to current block.timestamp + 5-10 minutes to allow time for the CoW auction to settle

### Multiple Operations with Same Parameters

If you need to execute identical operations in sequence:
- Increment the `deadline` value to create unique hash
- Without unique hash, second operation would fail hash uniqueness check
- Alternatively, wait for first operation to settle before submitting second

### Subaccount Usage

Using [EVC subaccounts](https://evc.wtf/docs/concepts/internals/sub-accounts) allows multiple separate positions to be held by the same account. EVC subaccounts are supported by the wrapper contracts.

If using subaccount:
- `account` must share the high 19 bits with `owner`
- Call `EVC.getInbox(owner, account)` to get the subaccount address
- Position collateral and debt will be stored in this account

## Gas Usage

Typical gas costs depend on vault configuration but expect additional ~500k gas above a standard CoW settlement.

## Error Scenarios

### Off-chain

There are a number of issues that could happen before the order even gets submitted on-chain

| Error | Cause | Solution |
|-------|-------|----------|
| API rejects the order | Order parameters are incorrect | Review order parameters |
| CoW does not execute the order, becomes expired | Many possible causes,  but most likely `buyAmount` is set too agressive and solvers are unwilling to solve the order | Review `buyAmount` computation logic |

### On-chain

It is reccomended to use tracing tools like `cast r <txhash>` to understand why an onchain transaction is failing.

| Error | Cause | Solution |
|-------|-------|----------|
| `NotASolver` | Caller is not authenticated solver | Only solvers can call wrappedSettle; execute through CoW API |
| `Unauthorized` | Invalid authorization (bad signature or expired hash) | Review off-chain signing logic |
| `OperationDeadlineExceeded` | Block timestamp > deadline | Increase deadline or resubmit |
| `SubaccountMustBeControlledByOwner` | Account doesn't share bits with owner | Use valid EVC subaccount |
| Account health check reverts | Position is undercollateralized | Increase collateral or reduce borrow |
| Settlement reverts | Swap didn't produce enough collateral | Increase buyAmount or improve price |

## Additional Resources

- [Ethereum Vault Connector Documentation](https://evc.wtf/)
- [CoW Protocol Documentation](https://docs.cow.fi/)
- [Euler Vault Documentation](https://docs.euler.finance/)
