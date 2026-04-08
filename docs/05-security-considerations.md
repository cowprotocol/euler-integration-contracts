# Security Considerations for Auditors and Integrators

## Executive Summary

The Euler-CoW integration wrappers are designed with multiple layers of security to prevent unauthorized actions and ensure safe fund management. This document details the threat model, security assumptions, and critical implementation details that auditors and integrators need to understand.

## Security Model

### Trusted Actors

**CoW Protocol Solvers**: Authenticated CoW Protocol solvers are assumed to be generally trustworthy as they:
- Are subject to slashing for disobeying the rules through CoW Protocol's bond mechanism
- Have economic incentive to provide good execution (competition for orders)
- If it is possible for the entire sum of a user's trade to be extracted, that could be a risk as it may exceed the size of the solver's bond

**[Euler EVC](https://evc.wtf/)**: A layer for coordinating vaults for money market and delayed position health checking operations.
- Has been audited by multiple agencies
- In production use
- Published [security considerations on their website](https://evc.wtf/docs/concepts/internals/security-considerations)

**CoW Settlement Contract**: Authenticated CoW Protocol solvers are assumed to be generally trustworthy as they:
- Has been audited by multiple agencies
- Remains in production use after many years
- List of known potential security issues is [maintained in documentation](https://docs.cow.fi/cow-protocol/reference/contracts/core#security--known-issues)


### User Authorization Requirements

All wrapper operations require explicit user authorization through one of:

1. **[EVC Permit Signature](https://evc.wtf/docs/concepts/internals/permit/)**: User signs an EIP-712 permit authorizing the specific operation
  - It is possible that not all fields of the user's `params` object are effectively accounted in the `EVC.permit`. To prevent issues with this, the hash of the user's `params` object is additionally appended to the end of the permit request
2. **Pre-Approved Hash**: User on-chain approves a specific operation hash
  - To prevent replay, a hash is *consumed* once it is used (or revoked by the user)

This ensures solvers cannot execute operations without user consent, even if they control the settlement contract.

## Threat Analysis

### What Solvers CAN Do (but shouldn't)

**1. Extract value within slashing bond limits**
Solvers could theoretically take all the surplus away from a user and transfer it to themselves. Due to the solver competition, only the order which returns the best surplus to the user will be selected, but this is not enforced by smart contracts or any decentralized process.

**2. Execute the order without executing the wrapper**
For different wrappers, this can have various different effects. For example, in the close position wrapper, in a contrived scenario where the user has 1) sufficient collateral ratio, 2) the required sellAmount of `sellToken` already in their wallet, their collateral could theoretically be swapped into the borrow asset and deposited into their Inbox account. The Inbox account provides mechanisms to allow the user to return their swap output (ex. through `getInbox()` to create the inbox, and then `callTransfer` to send tokens to the user's desired wallet).

This case is mitigated by a solver rule which prevents the execution of a CoW order without executing the user's requested wrappers, or be slashed.

**3. Execute the wrapper without executing the order**
Sort of the opposite of point (2) above. For different wrappers, this can have various different effects. For example, in the open position wrapper, a solver could open the position without actually converting the output borrowed asset back into the collateral asset and depositing into the subaccount. This would result in a user potentially being put close to liquidation if they already had a position open, depending on the situation.

This case is mitigated by a solver rule which prevents the execution of a CoW wrapper without executing the user's included order, or be slashed.

### What Solvers CANNOT Do

**1. Extract entire user deposits or positions**
- Cannot steal collateral or modify withdrawal amounts
- Clearing prices are bounded by user-signed limit prices
- Any clearing price below user's limit price causes trade to revert

**2. Alter operation parameters, or Fabricate an operation from nothing**
- All parameters are covered by user's EIP-712 signature or pre-approved hash
- Modifying any parameter (amount, vault, deadline) invalidates the authorization
- Wrapper validates parameter hash against user authorization

**4. Cause undercollateralization**
- EVC enforces account health checks at batch conclusion
- Any position that falls below minimum collateral ratio reverts
- Impossible to create undercollateralized position through normal flow

**5. Access funds outside the settlement**
- Wrapper only enables transfers between user account and settlement
- No arbitrary fund transfers possible

## Critical Security Properties

### 1. User Intent Validation

**Property**: Users control exactly what operation executes

**Mechanism**:
- Parameters are ABI-encoded and hashed using EIP-712
- User signs hash (or pre-approves it on-chain)
- Wrapper recomputes hash and validates against authorization
- Hash covers: owner, account, deadline, vault addresses, amounts

**Example**: User cannot be tricked into opening position with different vault:
```solidity
// User signs this:
hash = keccak256(abi.encode(params_with_eUSDC));

// If solver tries to use different vault:
params_with_eWETH = modifiedParams;
recomputedHash = keccak256(abi.encode(params_with_eWETH));
recomputedHash != hash  // INVALID - signature check fails
```

### 2. Parameter Binding to Authorization

**Property**: Authorization cannot be replayed with different parameters

**Mechanism**:
- `deadline` parameter must be unique per operation
- Each operation has unique hash due to deadline value
- Cannot execute two operations with same deadline
- Hash is tied to specific vaults, amounts, and deadline

**Implementation**: In [`CowEvcBaseWrapper._getApprovalHash()`](../../src/CowEvcBaseWrapper.sol):
```solidity
// Hash includes all parameters:
bytes32 structHash = keccak256(abi.encode(
    PARAMS_TYPE_HASH,
    owner,        // parameterized
    account,      // parameterized
    deadline,     // UNIQUE - prevents replay
    collateralVault,  // parameterized
    borrowVault,      // parameterized
    collateralAmount, // parameterized
    borrowAmount      // parameterized
));
```

### 3. Atomicity Within [EVC Batch](https://evc.wtf/docs/concepts/internals/batch)

**Property**: All operations succeed or revert together

**Mechanism**:
- All operations bundled in single `EVC.batch()` call
- EVC executes atomically - no intermediate states
- Account health checked once at batch conclusion

**Guarantee**: Cannot have partial execution where user has borrowed assets without collateral.

### 4. Reentrancy Protection

**Property**: Cannot execute nested operations that interfere with outer operation

**Mechanism**:
- `expectedEvcInternalSettleCallHash` stored in transient storage
- Wrapper validates callback hash matches expected hash
- Only correct callback can proceed

**Prevents**: Malicious settlement contract from calling wrapper again with different data

```solidity
function evcInternalSettle(...) external {
    require(msg.sender == address(EVC), Unauthorized(msg.sender));
    require(
        expectedEvcInternalSettleCallHash == keccak256(msg.data),
        InvalidCallback()
    );
    // Only correct data can proceed
}
```

### 5. Account Health Enforcement

**Property**: Positions cannot become undercollateralized

**Mechanism**:
- [EVC enforces account health checks](https://evc.wtf/docs/concepts/internals/account-status-checks/) at batch conclusion
- Minimum collateral ratio is vault-specific
- If health check fails, entire batch reverts

**Example**: 5x position (120% collateral ratio) must maintain ≥110% or position reverts

**Cannot be bypassed because**: Health check happens AFTER all operations, preventing any undercollateralization in committed state.

### 6. Solver Authentication

**Property**: Only authenticated solvers can initiate wrapped settlements

**Mechanism**:
```solidity
require(AUTHENTICATOR.isSolver(msg.sender), NotASolver(msg.sender));
```

**Note**: This is a courtesy check; not relied upon for security since anyone can call `EVC.batch()`. The real security is user authorization (permit/pre-approved hash).

## Known Risks and Mitigations

### Risk 1: Frontend Misconfiguration

**Scenario**: Frontend configures CoW order with wrong `receiver` address
```solidity
// WRONG:
GPv2Order.Data({
    receiver: 0xWrongAddress,  // Not the Inbox or subaccount!
    // ...
});
```

Furthermore but perhaps more difficult to detect, if an asset that is *not* an Euler Vault token is sent to the user's subaccount, it will become inaccessible because the EVC is required to access funds in a subaccount, which as neither an EOA nor smart contract.

**Impact**: Funds sent to inaccessible address after swap, lost

**Mitigation**:
- Validate receiver matches subaccount before submitting order. If using close position wrapper, use `getInbox`.
- Use helper functions to construct orders
- NOTE: in the case of the `ClosePositionWrapper`, there is some protection against this as it validates that tokens were received in the Inbox or revert before repay.

### Risk 2: Account Collateralization Border Cases

**Scenario**: Position is at exact minimum collateral ratio
- Small price movement can trigger liquidation
- Interest accrual gradually pushes position toward liquidation

**Mitigation**:
- Keep buffer above minimum (e.g., 120% instead of 110%)
- Monitor account health continuously
- Close or add collateral before reaching minimum

### Risk 3: Interest Accumulation in Close Operations

**Scenario**: When closing position with KIND_BUY order:
```solidity
// User calculates current debt: 5 ETH
// Sets buyAmount = 5e18
// But interest accumulated: 5.05 ETH now required
// Order fails - not enough debt asset produced
```

**Impact**: Close operation only repays the amount it can, position remains open with a very small amount of debt

**Mitigation**:
- Add buffer to buyAmount for KIND_BUY: `debt * 1.01` or `debt * 1.02`
- Check debt amount just before submitting order
- Use KIND_SELL with slippage protection for partial closes

### Risk 4: Inbox Usage Conflicts

**Scenario**: Multiple close operations submitted for same subaccount
- First operation's Inbox holds collateral
- Second operation tries to use same Inbox
- Conflict in fund custody

**Impact**: Second operation fails or blocks first

**Mitigation**:
- Do NOT submit multiple close operations for same subaccount simultaneously
- Wait for first operation to settle or expire (deadline) before submitting second
- Each subaccount should have at most one pending close operation

## Suggested Security Checklist

### For Auditors

- [ ] Verify EIP-712 domain separator computation (chain ID, contract address, name, version)
- [ ] Validate parameter hash includes all fields
- [ ] Check signature recovery is correctly validated for permit flow
- [ ] Verify deadline comparisons
- [ ] Verify that any relevant revert results in the whole transaction reverting
- [ ] Validate that the user cannot specify untrusted contracts (ex. arbitrary Euler vault contracts) to steal other user's funds or harm the solver
- [ ] Verify receiver address is correctly computed for Close position Inbox
- [ ] Check that old/new collateral routing in Collateral Swap is correct

### For Integrators

- [ ] Ensure correct computation of CoW order `receiver` address for each wrapper
- [ ] Set deadline to `block.timestamp + 5 minutes` or similar
- [ ] For Close Position wrapper, using `KIND_BUY` orders (full close), add a small buffer to debt amount
- [ ] For KIND_SELL orders (partial close), set appropriate slippage limit
- [ ] Wait for previous order to expire before submitting new operation for same subaccount
- [ ] Validate operation parameters correspond to CoW order parameters as documented
- [ ] Verify resulting account collateralization is safe before submitting order
- [ ] Provide a system for monitoring (ex. email notifications) for account health after opening positions

## Vault-Specific Considerations

### Loan-to-Value (LTV) Ratios

Different vault pairs have different LTV ratios. The protocol inherits these from Euler:

- **Opening Position**: Must maintain ≥110% collateral ratio (or vault-specific minimum)
- **Closing Position**: Remaining collateral must cover remaining debt at new LTV
- **Collateral Swap**: New collateral must have sufficient LTV to cover debt

**Security implication**: LTV enforcement is handled by Euler protocol through EVC, not by wrappers.

### Vault Enabling/Disabling

The wrappers enable vaults as:
- **Collateral**: "This can be borrowed against"
- **Controller**: "This is where debt is located"

Vault enabling is idempotent (already-enabled vaults can be enabled again without harm).

## Cryptographic Security

### EIP-712 Domain Separator

Each wrapper computes unique domain separator:
```solidity
keccak256(abi.encode(
    DOMAIN_TYPE_HASH,
    keccak256("CowEvcOpenPositionWrapper"),  // name
    keccak256("1"),                          // version
    block.chainid,                           // prevents cross-chain replay
    address(this)                            // wrapper-specific
))
```

**Security properties**:
- Prevents cross-chain replay attacks
- Prevents replay across different wrapper versions
- Unique per wrapper address (no copy-paste vulnerabilities)

### Signature Validation

Permit signatures are validated through `EVC.permit()`:
- EVC handles signature recovery
- Nonce prevents replay
- Timestamp validates deadline

Wrapper validates signature through this EVC call, NOT independently.

## Common Vulnerability Classes and Mitigations

| Vulnerability | How Mitigated |
|---------------|---------------|
| **Signature Replay** | EIP-712 domain separator, unique deadline, EVC nonce |
| **Parameter Tampering** | Hash validation before execution |
| **Reentrancy** | Transient storage hash check |
| **Undercollateralization** | EVC health check at batch end |
| **Unauthorized Fund Transfer** | Permit/pre-approved hash validation |
| **Cross-Chain Replay** | Chain ID in domain separator |
| **Front-Running** | EVC batch atomicity, no intermediate states |
| **Fund Loss in Receiver Misconfiguration** | Integrator responsibility (validated in docs) |

## Edge Cases and Boundary Conditions

### Edge Case 1: Zero Collateral Amount

**Open Position**: Setting `collateralAmount = 0` means no new collateral deposited (vault already has margin)
- Allowed - position opened with existing collateral
- Verify vault has sufficient collateral before setting to 0

### Edge Case 2: Large Position Amounts

**All operations**: Very large amounts may cause:
- Slippage due to market depth
- Gas limit issues (though unlikely with modern chains)

**Mitigation**: CoW order parameters should reflect market conditions

### Edge Case 3: Vault Pause/Suspension

If Euler vault is paused:
- Enable vault call may fail
- Deposit/borrow/withdraw calls may fail
- EVC batch reverts

**Impact**: Operation fails safely (reverted, not partial)

### Edge Case 4: Interest Rate Changes

Interest rates change dynamically in Euler vaults:
- Close operation's debt calculation may become stale
- If order takes time to settle, actual debt may increase
- KIND_BUY orders require sufficient buyAmount buffer

**Mitigation**: Add interest buffer when computing amounts

## References and Related Work

- **EIP-712**: [Typed Structured Data Hashing](https://eips.ethereum.org/EIPS/eip-712)
- **EVC**: [Ethereum Vault Connector Security Model](https://evc.wtf/docs/concepts/security/)
- **CoW Protocol**: [Solver Slashing Mechanism](https://docs.cow.fi/)
- **Euler Vaults**: [Risk Parameters](https://docs.euler.finance/concepts/core/account-health/)
- **EIP-1271**: [Contract Signature Validation](https://eips.ethereum.org/EIPS/eip-1271)