### Title
Zero `priceProviderTimelock` Bypasses Oracle Rotation Delay, Enabling Instant Bad-Price Execution — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`_validatePoolParameters` does not enforce a minimum value for `params.priceProviderTimelock` when the pool is in mutable-oracle mode. A pool creator can set `priceProviderTimelock = 0`, which causes `proposePoolPriceProvider` to compute `executeAfter = block.timestamp + 0 = block.timestamp`. The guard in `executePoolPriceProviderUpdate` (`block.timestamp < execAfter`) is then immediately false, so the pool admin can propose and execute an oracle swap atomically in the same block — completely nullifying the timelock that was introduced specifically to prevent instant oracle manipulation.

---

### Finding Description

`createPool` is permissionless. Any caller can supply `PoolParameters` with `priceProviderTimelock = 0` (any value other than `type(uint256).max` is treated as mutable mode). `_validatePoolParameters` validates tokens, fees, admin address, and initial amounts, but contains **no check on `priceProviderTimelock`**:

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol
function _validatePoolParameters(PoolParameters calldata params) internal view {
    if (params.token0 == address(0) || ...) revert InvalidTokenConfig();
    if (params.admin == address(0)) revert InvalidAdmin();
    _validatePriceProvider(params.token0, params.token1, params.priceProvider);
    if (params.adminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
    if (params.initialAmount0PerShareE18 == 0 ...) revert InvalidInitialAmount();
    if (params.minimalMintableLiquidity == 0) revert InvalidMinimalMintableLiquidity();
    // ← no check on priceProviderTimelock
}
```

The value is stored verbatim:

```solidity
priceProviderTimelock[pool] = params.priceProviderTimelock; // can be 0
```

When the pool admin later calls `proposePoolPriceProvider`:

```solidity
uint256 timelock = priceProviderTimelock[pool]; // 0
uint256 executeAfter = block.timestamp + timelock; // = block.timestamp
pendingPriceProviderExecuteAfter[pool] = executeAfter;
```

And immediately calls `executePoolPriceProviderUpdate` in the same block:

```solidity
if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(...);
// block.timestamp < block.timestamp → false → does NOT revert
```

The new oracle is applied with zero delay.

---

### Impact Explanation

The pool admin (semi-trusted) can atomically replace the pool's price provider with a malicious oracle that returns an arbitrarily manipulated bid/ask quote. Every subsequent swap executes against that bad price. Because the pool is oracle-driven (no internal price discovery), the manipulated quote directly controls how many tokens the pool pays out per swap. An attacker controlling the oracle can set bid/ask such that swappers receive far more than the pool's reserves can cover, or drain LP balances in a single block. This is a direct loss of LP principal — the exact impact class listed as in-scope ("bad-price execution: stale, inverted, unbounded, or unclamped bid/ask quote reaches a pool swap").

The timelock mechanism was introduced precisely to prevent this attack (documented in `AuditFindings.md` M01: "Admin can arbitrarily change the pool priceProvider"). Allowing `priceProviderTimelock = 0` silently re-opens the same attack surface.

---

### Likelihood Explanation

`createPool` is permissionless. Any actor can deploy a pool with `priceProviderTimelock = 0` and attract LP deposits (e.g., by seeding liquidity and advertising competitive fees). LPs have no on-chain enforcement that a meaningful delay exists; they must manually inspect `priceProviderTimelock[pool]` off-chain. The pool admin can then execute the oracle swap and drain the pool in a single transaction. Likelihood is **Medium** — it requires a malicious pool creator/admin, but the factory provides no protection against this configuration.

---

### Recommendation

In `_validatePoolParameters`, reject any `priceProviderTimelock` value that is neither `type(uint256).max` (immutable mode) nor at least some protocol-defined minimum (e.g., 1 hour or 24 hours):

```solidity
uint256 MIN_PRICE_PROVIDER_TIMELOCK = 1 hours; // example

if (params.priceProviderTimelock != type(uint256).max &&
    params.priceProviderTimelock < MIN_PRICE_PROVIDER_TIMELOCK) {
    revert InvalidPriceProviderTimelock();
}
```

This mirrors the pattern already used for fee caps and ensures the timelock is always meaningful when the oracle is mutable.

---

### Proof of Concept

```solidity
// 1. Deploy pool with zero timelock (mutable mode)
PoolParameters memory params = ...;
params.priceProviderTimelock = 0; // not type(uint256).max → mutable, no delay
address pool = factory.createPool(params);

// 2. LPs deposit into the pool (attracted by normal initial oracle)
pool.addLiquidity(...);

// 3. Pool admin atomically rotates to malicious oracle in one block
MaliciousOracle mal = new MaliciousOracle();
mal.setBidAndAskPrice(type(uint128).max, 1); // extreme manipulation

vm.prank(admin);
factory.proposePoolPriceProvider(pool, address(mal));
// executeAfter = block.timestamp + 0 = block.timestamp

vm.prank(admin);
factory.executePoolPriceProviderUpdate(pool); // passes: block.timestamp < block.timestamp → false

// 4. Next swap executes at manipulated price → LP funds drained
pool.swap(attacker, largeAmount, "");
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L212-213)
```text
    poolAdmin[pool] = params.admin;
    priceProviderTimelock[pool] = params.priceProviderTimelock;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L481-490)
```text
    uint256 timelock = priceProviderTimelock[pool];
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, newPriceProvider);

    address mutableProvider = PoolStateLibrary._slot3(pool);
    address current = mutableProvider != address(0) ? mutableProvider : p.immutablePriceProvider;
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L497-499)
```text
    uint256 execAfter = pendingPriceProviderExecuteAfter[pool];
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L548-563)
```text
  function _validatePoolParameters(PoolParameters calldata params) internal view {
    if (params.token0 == address(0) || params.token1 == address(0) || params.token0 == params.token1) {
      revert InvalidTokenConfig();
    }
    if (params.admin == address(0)) revert InvalidAdmin();
    _validatePriceProvider(params.token0, params.token1, params.priceProvider);
    if (params.adminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    if (spreadProtocolFeeE6 > maxProtocolSpreadFeeE6) revert ProtocolFeeTooHigh();
    if (protocolNotionalFeeE8 > maxProtocolNotionalFeeE8) revert ProtocolFeeTooHigh();
    if (params.adminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (params.adminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();
    if (params.initialAmount0PerShareE18 == 0 || params.initialAmount1PerShareE18 == 0) {
      revert InvalidInitialAmount();
    }
    if (params.minimalMintableLiquidity == 0) revert InvalidMinimalMintableLiquidity();
  }
```

**File:** metric-core/contracts/types/FactoryOperation.sol (L17-18)
```text
  /// @notice Delay for mutable provider rotation; `type(uint256).max` means immutable provider.
  uint256 priceProviderTimelock;
```

**File:** metric-core/docs/AuditFindings.md (L45-69)
```markdown
## M01 - Admin can arbitrarily change the pool priceProvider

### Finding summary

`setPriceProvider()` allowed admin to replace oracle at runtime, and `priceProvider` was returned by `getImmutables()`.

### Resolution

Fixed.

Changes:

- Added constructor config `priceProviderTimelock`.
- Added admin flow:
  - `proposePriceProvider(address newPriceProvider)`
  - `executePriceProviderUpdate()`
- Added events:
  - `PriceProviderChangeProposed(currentPriceProvider, newPriceProvider, executeAfter)`
  - `PriceProviderUpdated(newPriceProvider)`

Behavior now:

- `priceProviderTimelock == type(uint256).max` => immutable mode (admin updates disabled).
- `priceProviderTimelock < type(uint256).max` => mutable mode with delayed execution.
- Price provider used by swaps/reports resolves through timelock mode; active provider is read via `MetricOmmPoolStateView.priceProvider(pool)`.
```
