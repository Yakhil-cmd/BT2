Now I have enough context to complete the analysis. Let me verify the exact timelock check logic:### Title
Pool Admin Bypasses Price-Provider Timelock via Zero-Delay Deployment — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
A pool created with `priceProviderTimelock = 0` (any value other than `type(uint256).max`) stores a zero-second delay. The pool admin can then call `proposePoolPriceProvider` and `executePoolPriceProviderUpdate` in the same block — or even the same transaction via multicall — to atomically swap the oracle to an arbitrary address, defeating the timelock that was introduced specifically to fix audit finding M01.

### Finding Description

`_validatePoolParameters` enforces no minimum on `priceProviderTimelock` beyond the binary `type(uint256).max` / anything-else split: [1](#0-0) 

When `priceProviderTimelock = 0` is passed, the factory stores it verbatim: [2](#0-1) 

`proposePoolPriceProvider` computes `executeAfter = block.timestamp + timelock`, which equals `block.timestamp` when `timelock == 0`: [3](#0-2) 

`executePoolPriceProviderUpdate` guards with a strict-less-than check: [4](#0-3) 

Because `block.timestamp < block.timestamp` is always `false`, the revert never fires. The pool admin can call both functions in the same block (or atomically via a multicall wrapper) and the new oracle is live immediately.

The timelock was added to fix M01 ("Admin can arbitrarily change the pool priceProvider"): [5](#0-4) 

A zero-delay deployment fully restores the pre-fix behaviour.

### Impact Explanation

The oracle is the sole source of bid/ask prices for every swap. An immediately-substituted malicious oracle can return inverted, stale, or unbounded prices, allowing the pool admin to drain LP funds through bad-price execution. This matches the "Bad-price execution" and "Admin-boundary break" allowed impacts: the pool admin bypasses the timelock that is the only cap on oracle-rotation power.

### Likelihood Explanation

Any caller of `createPool` controls `priceProviderTimelock`. A pool admin who is also the pool creator (the common case) can trivially set it to `0`. The two-step propose/execute sequence is callable in a single transaction via any multicall wrapper, leaving LPs no window to observe the pending change and exit.

### Recommendation

Enforce a minimum non-zero timelock in `_validatePoolParameters` for mutable-oracle pools:

```solidity
// in _validatePoolParameters
if (params.priceProviderTimelock != type(uint256).max && params.priceProviderTimelock == 0) {
    revert TimelockTooShort();
}
```

Or more robustly, require a protocol-defined minimum (e.g. 24 hours) so that LPs always have a reaction window.

### Proof of Concept

```solidity
// 1. Deploy pool with zero timelock (not immutable, but no delay)
PoolParameters memory p = _defaultParams();
p.priceProviderTimelock = 0;          // <-- zero, not type(uint256).max
address pool = factory.createPool(p);

// 2. Prepare a malicious oracle
MaliciousOracle bad = new MaliciousOracle();
bad.setTokens(p.token0, p.token1);
bad.setBidAndAskPrice(0, type(uint128).max); // inverted / unbounded

// 3. Pool admin atomically proposes and executes in the same block
vm.startPrank(admin);
factory.proposePoolPriceProvider(pool, address(bad));
// executeAfter == block.timestamp → strict-less-than check passes immediately
factory.executePoolPriceProviderUpdate(pool);
vm.stopPrank();

// 4. Oracle is now the malicious one — no timelock elapsed
address active = PoolStateLibrary._slot3(pool);
assertEq(active, address(bad)); // passes
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L213-213)
```text
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
