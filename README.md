# Euler-CoW Protocol Integration Contracts

Smart contracts enabling leveraged position management through CoW Protocol settlements combined with Ethereum Vault Connector (EVC) operations.

## Documentation

See the `docs/` folder for complete documentation:

- **[Overview](./docs/01-overview.md)** - Architecture and wrapper patterns
- **[Opening Positions](./docs/02-open-position.md)** - Using `CowEvcOpenPositionWrapper`
- **[Closing Positions](./docs/03-close-position.md)** - Using `CowEvcClosePositionWrapper`
- **[Collateral Swaps](./docs/04-collateral-swap.md)** - Using `CowEvcCollateralSwapWrapper`
- **[Security Considerations](./docs/05-security-considerations.md)** - Security Considerations and things to be aware of

## Quick Start

### Build
```bash
forge build --deny notes
```

### Test
```bash
export FORK_RPC_URL=https://mainnet.example.com/rpc
forge test
```

### Format
```bash
forge fmt
```

## Project Structure

- `src/` - Wrapper contracts and related utilities
- `test/` - Unit and integration tests
- `lib/` - External dependencies (Euler, EVC, CoW Protocol)

## Dependencies

- [Ethereum Vault Connector (EVC)](https://evc.wtf/)
- [Euler Vaults](https://docs.euler.finance/)
- [CoW Protocol](https://docs.cow.fi/)

## License

Dual licensed under MIT OR Apache-2.0.
