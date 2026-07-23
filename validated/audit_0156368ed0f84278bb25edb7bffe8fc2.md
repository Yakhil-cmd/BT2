Looking at the codebase, I need to trace the analog of "mandatory external call on every core operation that can revert → DoS of core functionality" through Metric OMM's extension framework and liquidity removal path.

**Key observations:**

1. `removeLiquidity` deliberately omits `whenNotPaused` — the protocol's stated invariant is that LPs can always exit.
2. `removeLiquidity` unconditionally calls `_beforeRemoveLiquidity` and `_afterRemoveLiquidity`, which invoke `_callExtensionsInOrder` → `CallExtension.callExtension(extension, data)` with no try-catch.
3. Extensions are stored as immutables (`EXTENSION_1`–`EXTENSION_7`) and `BEFORE_REMOVE_LIQUIDITY_ORDER`/`AFTER_REMOVE_LIQUIDITY_ORDER` are also immutable — there is no mechanism to disable a broken extension post-deployment.

---

### Title
Immutable extension calls on `removeLiquidity` can permanently DoS LP withdrawals — (`metric-core/contracts/ExtensionCalling.sol`, `metric-core/contracts/MetricOmmPool.sol`)

### Summary
`removeLiquidity` omits `whenNotPaused` to guarantee LPs can always exit, but unconditionally invokes `_beforeRemoveLiquidity` / `_afterRemoveLiquidity`, which call immutable extension contracts without any try-catch. If an extension configured for the remove-liquidity hooks becomes permanently broken — due to an external oracle dependency failing, the extension contract being self-destructed, or any other non-malicious external failure — every `removeLiquidity` call reverts, permanently locking LP principal with no admin escape hatch.

### Finding Description

`MetricOmmPool.removeLiquidity` skips the `whenNotPaused` guard intentionally: [1](#0-0) 

Before and after the actual state change it calls: [2](#0-1) 

Those helpers delegate to `_callExtensionsInOrder`, which iterates the packed order word and calls each configured extension with no error isolation: [3](#0-2) 

The extension addresses and hook-order words are all stored as immutables set once at construction: [4](#0-3) 

There is no factory function to clear or replace a broken extension after deployment. `setPriceProvider` exists for the price provider, but no equivalent exists for extensions. [5](#0-4) 

Production extensions such as `OracleValueStopLossExtension` and `PriceVelocityGuardExtension` have external oracle dependencies. If those dependencies revert (oracle paused, stale, decommissioned), the extension reverts, `_beforeRemoveLiquidity` reverts, and `removeLiquidity` reverts — permanently, because the extension binding is immutable.

### Impact Explanation
LPs cannot withdraw their funds. This is a direct, permanent loss of access to user principal with no admin recovery path. It matches the "unusable withdraw/liquidity flows" and "broken core pool functionality causing loss of funds" criteria in the allowed impact gate.

### Likelihood Explanation
Any pool that configures a production extension (e.g., `OracleValueStopLossExtension`, `PriceVelocityGuardExtension`) on the `BEFORE_REMOVE_LIQUIDITY_ORDER` or `AFTER_REMOVE_LIQUIDITY_ORDER` hook is exposed. Oracle dependencies can fail for non-malicious reasons identical to those in the seed report: feed decommissioning, staleness, circuit-breaker activation, or the oracle contract being paused. The trigger requires no privileged action after pool creation.

### Recommendation
Wrap extension calls inside `_beforeRemoveLiquidity` and `_afterRemoveLiquidity` in try-catch blocks that silently continue on failure (mirroring the mitigation suggested in the seed report). Alternatively, add a factory-level emergency function that allows the factory owner to zero out a specific extension slot for a specific pool when that extension is provably broken, preserving the "LP exit always works" invariant.

### Proof of Concept
1. Pool is deployed with `PriceVelocityGuardExtension` (or any oracle-dependent extension) registered at `BEFORE_REMOVE_LIQUIDITY_ORDER = 1` (extension index 1).
2. The extension's oracle feed is decommissioned or paused by the oracle operator.
3. LP calls `removeLiquidity`.
4. `_beforeRemoveLiquidity` → `_callExtensionsInOrder` → `CallExtension.callExtension(extension, data)` → extension calls its oracle → oracle reverts.
5. The revert propagates up through `_callExtensionsInOrder` (no try-catch) → `_beforeRemoveLiquidity` → `removeLiquidity`.
6. LP's transaction reverts. Repeating indefinitely: LP funds are permanently locked with no admin escape hatch, because the extension address is an immutable and no factory function can clear it.

### Citations

**File:** metric-core/contracts/MetricOmmPool.sol (L199-212)
```text
  function removeLiquidity(address owner, uint80 salt, LiquidityDelta calldata deltas, bytes calldata extensionData)
    external
    nonReentrant(PoolActions.REMOVE_LIQUIDITY)
    returns (uint256 amount0Removed, uint256 amount1Removed)
  {
    if (deltas.binIdxs.length == 0) return (0, 0);
    if (deltas.binIdxs.length != deltas.shares.length) revert LiquidityDeltaLengthMismatch();
    if (msg.sender != owner) revert NotPositionOwner();
    _beforeRemoveLiquidity(msg.sender, owner, salt, deltas, extensionData);
    (amount0Removed, amount1Removed) = LiquidityLib.removeLiquidity(
      _liquidityContext(), owner, salt, deltas, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterRemoveLiquidity(msg.sender, owner, salt, deltas, amount0Removed, amount1Removed, extensionData);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L477-480)
```text
  function setPriceProvider(address newPriceProvider) external onlyFactory {
    priceProvider = newPriceProvider;
    emit PriceProviderUpdated(newPriceProvider);
  }
```

**File:** metric-core/contracts/ExtensionCalling.sol (L17-51)
```text
  address internal immutable EXTENSION_1;
  address internal immutable EXTENSION_2;
  address internal immutable EXTENSION_3;
  address internal immutable EXTENSION_4;
  address internal immutable EXTENSION_5;
  address internal immutable EXTENSION_6;
  address internal immutable EXTENSION_7;
  /// @dev Order of extension calls for before add liquidity.
  uint256 internal immutable BEFORE_ADD_LIQUIDITY_ORDER;
  /// @dev Order of extension calls for after add liquidity.
  uint256 internal immutable AFTER_ADD_LIQUIDITY_ORDER;
  /// @dev Order of extension calls for before remove liquidity.
  uint256 internal immutable BEFORE_REMOVE_LIQUIDITY_ORDER;
  /// @dev Order of extension calls for after remove liquidity.
  uint256 internal immutable AFTER_REMOVE_LIQUIDITY_ORDER;
  /// @dev Order of extension calls for before swap.
  uint256 internal immutable BEFORE_SWAP_ORDER;
  /// @dev Order of extension calls for after swap.
  uint256 internal immutable AFTER_SWAP_ORDER;

  constructor(PoolExtensions memory extensions, ExtensionOrders memory extensionOrders) {
    EXTENSION_1 = extensions.extension1;
    EXTENSION_2 = extensions.extension2;
    EXTENSION_3 = extensions.extension3;
    EXTENSION_4 = extensions.extension4;
    EXTENSION_5 = extensions.extension5;
    EXTENSION_6 = extensions.extension6;
    EXTENSION_7 = extensions.extension7;
    BEFORE_ADD_LIQUIDITY_ORDER = extensionOrders.beforeAddLiquidity;
    AFTER_ADD_LIQUIDITY_ORDER = extensionOrders.afterAddLiquidity;
    BEFORE_REMOVE_LIQUIDITY_ORDER = extensionOrders.beforeRemoveLiquidity;
    AFTER_REMOVE_LIQUIDITY_ORDER = extensionOrders.afterRemoveLiquidity;
    BEFORE_SWAP_ORDER = extensionOrders.beforeSwap;
    AFTER_SWAP_ORDER = extensionOrders.afterSwap;
  }
```

**File:** metric-core/contracts/ExtensionCalling.sol (L75-86)
```text
  function _callExtensionsInOrder(uint256 order, bytes memory data) private {
    if (order == 0) return;

    while (true) {
      uint256 extensionIndex = order & 0x7;
      if (extensionIndex == 0) break;
      address extension = _extensionAddress(extensionIndex);
      if (extension == address(0)) revert PanicEmptyExtension();
      CallExtension.callExtension(extension, data);
      order >>= 3;
    }
  }
```
