### Title
Unguarded Extension Calls in `_callExtensionsInOrder` Permanently Brick Pool Swap and LP Withdrawal When Any Extension Reverts — (File: `metric-core/contracts/ExtensionCalling.sol`)

---

### Summary

`ExtensionCalling._callExtensionsInOrder` loops over up to seven immutable extension slots and calls each via `CallExtension.callExtension`, which unconditionally propagates any revert from the extension contract. Because extensions are immutable after deployment and are invoked on every `swap`, `addLiquidity`, and `removeLiquidity` call, a single extension that begins reverting due to state-dependent logic or external conditions permanently bricks all three core operations for that pool, trapping LP principal with no recovery path.

---

### Finding Description

`_callExtensionsInOrder` (ExtensionCalling.sol line 75–86) iterates over the packed `order` word, resolves each extension address, and calls `CallExtension.callExtension`. `callExtension` (CallExtension.sol line 8–31) performs a raw `.call` and, on failure, re-reverts with the extension's revert data or `ExtensionCallFailed()`. There is no try/catch, no skip-on-failure path, and no circuit-breaker. [1](#0-0) [2](#0-1) 

This function is invoked for all six hooks:

- `_beforeSwap` / `_afterSwap` → inside `swap()` (MetricOmmPool.sol lines 230–295)
- `_beforeAddLiquidity` / `_afterAddLiquidity` → inside `addLiquidity()` (lines 191–195)
- `_beforeRemoveLiquidity` / `_afterRemoveLiquidity` → inside `removeLiquidity()` (lines 207–211) [3](#0-2) [4](#0-3) 

Extensions are stored as immutable variables (`EXTENSION_1` … `EXTENSION_7`) and cannot be replaced after pool deployment. [5](#0-4) 

The factory validates extension addresses and order indices at creation time via `ValidateExtensionsConfig.validateExtensionsConfig`, but it only checks that indices are in-range and non-duplicate — it does not and cannot guarantee that an extension will never revert in the future. [6](#0-5) 

The factory also calls `initialize` on each extension during `createPool`, confirming the extension is live at creation time, but this provides no guarantee about future behavior. [7](#0-6) 

**Concrete revert scenarios (analogous to the original report's oracle/token revert scenarios):**

1. **Velocity-guard extension**: Tracks cumulative swap volume and reverts once a daily cap is exceeded. Any unprivileged trader can push volume to the cap, after which `_beforeRemoveLiquidity` reverts for all LPs.
2. **Stop-loss extension**: Reverts when the oracle price crosses a configured level. Normal price movement triggers it; if registered for `beforeRemoveLiquidity`, LPs cannot exit.
3. **Allowlist extension**: Delegates to an external registry contract. If that registry is upgraded, paused, or self-destructs, the extension reverts on every call.

In all three cases the extension was legitimate at pool creation (the factory's `initialize` call succeeded), but later begins reverting due to external state — permanently locking LP funds with no admin recovery path.

---

### Impact Explanation

- `removeLiquidity` reverts → LPs cannot withdraw principal → **direct loss of user funds** (funds are not stolen but are permanently inaccessible).
- `swap` reverts → pool is untradeable → protocol and admin fee revenue is lost.
- `addLiquidity` reverts → no new liquidity can enter.
- Because extensions are immutable, neither the pool admin nor the factory owner has any on-chain mechanism to disable a broken extension. The pool is permanently bricked.

---

### Likelihood Explanation

- Extensions with state-dependent behavior (velocity guards, stop-losses, allowlists) are the explicitly documented use cases for the extension system.
- The revert condition in the velocity-guard scenario can be reached by any unprivileged user through normal trading activity — no privileged action is required.
- The pool admin cannot fix the situation post-deployment because extension addresses are immutable.
- The factory's `ValidateExtensionsConfig` check provides no protection against future reverts.

---

### Recommendation

1. **Wrap extension calls in try/catch** inside `_callExtensionsInOrder`. On failure, emit an event and either skip the extension or revert with a pool-level error that allows the factory to intervene.
2. **Distinguish hook semantics**: "blocking" hooks (allowed to revert to block an operation, e.g., `beforeSwap`) vs. "informational" hooks (must never block, e.g., `afterRemoveLiquidity`). Enforce this distinction at the `ValidateExtensionsConfig` level and handle failures differently per hook type.
3. **Add an emergency extension-disable path**: A factory-owner function that can zero out a specific extension slot on a pool (requires making extension addresses mutable with appropriate access control and timelock).

---

### Proof of Concept

1. Deploy a pool with a velocity-guard extension registered for `BEFORE_REMOVE_LIQUIDITY_ORDER`.
2. The velocity guard tracks cumulative swap volume and reverts once a daily cap is exceeded.
3. An attacker (or normal market activity) executes swaps totaling the daily cap.
4. Any subsequent call to `removeLiquidity` reverts: `removeLiquidity` → `_beforeRemoveLiquidity` → `_callExtensionsInOrder` → `CallExtension.callExtension(velocityGuard, ...)` → velocity guard reverts → `callExtension` re-reverts → entire transaction reverts.
5. LPs cannot withdraw; their funds are locked. Because extensions are immutable, there is no on-chain recovery path.

### Citations

**File:** metric-core/contracts/ExtensionCalling.sol (L17-35)
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

**File:** metric-core/contracts/libraries/CallExtension.sol (L8-17)
```text
  function callExtension(address extension, bytes memory data) internal {
    (bool success, bytes memory result) = extension.call(data);
    if (!success) {
      if (result.length > 0) {
        assembly ("memory-safe") {
          revert(add(result, 32), mload(result))
        }
      }
      revert ExtensionCallFailed();
    }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L191-195)
```text
    _beforeAddLiquidity(msg.sender, owner, salt, deltas, extensionData);
    (amount0Added, amount1Added) = LiquidityLib.addLiquidity(
      _liquidityContext(), owner, salt, deltas, callbackData, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterAddLiquidity(msg.sender, owner, salt, deltas, amount0Added, amount1Added, extensionData);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L207-211)
```text
    _beforeRemoveLiquidity(msg.sender, owner, salt, deltas, extensionData);
    (amount0Removed, amount1Removed) = LiquidityLib.removeLiquidity(
      _liquidityContext(), owner, salt, deltas, binTotals, _binStates, _binTotalShares, _positionBinShares
    );
    _afterRemoveLiquidity(msg.sender, owner, salt, deltas, amount0Removed, amount1Removed, extensionData);
```

**File:** metric-core/contracts/libraries/ValidateExtensionsConfig.sol (L14-42)
```text
  function validateExtensionsConfig(
    address[] calldata extensions,
    ExtensionOrders calldata orders,
    bytes[] calldata extensionInitData
  ) internal pure {
    if (extensions.length > MAX_EXTENSIONS) revert InvalidExtensionsConfig();
    if (extensionInitData.length != extensions.length) revert InvalidExtensionsConfig();

    if (extensions.length == 0) {
      if (!_ordersAreZero(orders)) revert InvalidExtensionsConfig();
      return;
    }

    for (uint256 i = 0; i < extensions.length; i++) {
      if (extensions[i] == address(0)) revert InvalidExtensionsConfig();
      for (uint256 j = 0; j < i; j++) {
        if (extensions[i] == extensions[j]) revert InvalidExtensionsConfig();
      }
    }

    if (_ordersAreZero(orders)) revert InvalidExtensionsConfig();

    _validateExtensionOrder(orders.beforeAddLiquidity, extensions.length);
    _validateExtensionOrder(orders.afterAddLiquidity, extensions.length);
    _validateExtensionOrder(orders.beforeRemoveLiquidity, extensions.length);
    _validateExtensionOrder(orders.afterRemoveLiquidity, extensions.length);
    _validateExtensionOrder(orders.beforeSwap, extensions.length);
    _validateExtensionOrder(orders.afterSwap, extensions.length);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L206-210)
```text
    for (uint256 i = 0; i < params.extensions.length; i++) {
      CallExtension.callExtension(
        params.extensions[i], abi.encodeCall(IMetricOmmExtensions.initialize, (pool, params.extensionInitData[i]))
      );
    }
```
