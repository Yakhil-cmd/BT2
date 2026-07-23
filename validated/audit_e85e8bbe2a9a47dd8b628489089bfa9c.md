### Title
`protocolUnpausePool` Ignores Prior Pause State, Leaving Originally-Active Pools Permanently Stuck in Admin-Paused State — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`MetricOmmPoolFactory.protocolUnpausePool` always transitions the pool to pause level `1` (admin-paused), regardless of whether the pool was at level `0` (active) or level `1` (admin-paused) before the protocol pause. Because `protocolPausePool` accepts both level `0` and level `1` as valid source states but stores no record of which one it came from, the unpause path cannot distinguish them and unconditionally lands on `1`. A pool that was fully active before a protocol pause is therefore left in admin-paused state after the protocol unpauses it, silently breaking swap functionality until the pool admin separately calls `unpausePool`.

---

### Finding Description

The pool tracks three pause levels:

| Level | Meaning |
|---|---|
| `0` | Active — swaps permitted |
| `1` | Admin-paused — swaps blocked |
| `2` | Protocol-paused — swaps blocked |

`protocolPausePool` accepts **both** level `0` and level `1` as valid source states and transitions to `2`:

```solidity
// MetricOmmPoolFactory.sol lines 392-396
function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}
``` [1](#0-0) 

`protocolUnpausePool` then **always** transitions to `1`, ignoring which level the pool was at before the protocol pause:

```solidity
// MetricOmmPoolFactory.sol lines 398-403
function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);   // ← always 1, never 0
}
``` [2](#0-1) 

The `whenNotPaused` modifier on `swap` blocks execution for **any** non-zero pause level:

```solidity
function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
}
``` [3](#0-2) 

So after the sequence `0 → 2 → 1`, the pool is in admin-paused state even though the admin never issued a pause. The only recovery path is the admin calling `unpausePool`, which requires `cur == 1`:

```solidity
function unpausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
}
``` [4](#0-3) 

No prior-state is stored anywhere in `protocolPausePool`, so `protocolUnpausePool` has no information to restore the original level.

---

### Impact Explanation

After a `protocolPausePool` / `protocolUnpausePool` cycle on a pool that was at level `0`:

- **Swaps are blocked** — `swap()` reverts with `PoolPaused()` at level `1`, identical to level `2`. Traders cannot execute any trades.
- **LP fee accrual stops** — no swaps means no spread or notional fees accumulate for LPs.
- **The pool admin is silently burdened** — they must discover the unexpected state and call `unpausePool` to restore activity. If the admin is a multisig or DAO with a slow execution path, the pool can remain broken for an extended period.
- **No direct fund loss**, but core swap functionality is rendered unusable without any admin action having caused it.

This satisfies the "Broken core pool functionality causing unusable swap flows" criterion.

---

### Likelihood Explanation

The trigger is a routine protocol governance action: pause then unpause. Any pool that was active (`level == 0`) at the time of a protocol pause will be affected. This is the common case — most pools are expected to be active. The likelihood is **High**.

---

### Recommendation

Store the pre-pause level in `protocolPausePool` and restore it in `protocolUnpausePool`:

```solidity
mapping(address => uint8) public priorPauseLevelBeforeProtocolPause;

function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    priorPauseLevelBeforeProtocolPause[pool] = cur;   // ← record prior state
    IMetricOmmPoolFactoryActions(pool).setPause(2);
}

function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    uint8 restore = priorPauseLevelBeforeProtocolPause[pool];
    delete priorPauseLevelBeforeProtocolPause[pool];
    IMetricOmmPoolFactoryActions(pool).setPause(restore);   // ← restore 0 or 1
}
```

---

### Proof of Concept

1. Pool is deployed and active: `pauseLevel == 0`.
2. Protocol owner calls `protocolPausePool(pool)`. Check passes (`cur == 0`). Pool transitions to `pauseLevel == 2`.
3. Protocol owner calls `protocolUnpausePool(pool)`. Check passes (`cur == 2`). Pool transitions to `pauseLevel == 1`.
4. Any user calls `pool.swap(...)`. `_checkNotPaused()` fires: `pauseLevel (1) != 0` → `revert PoolPaused()`.
5. Pool admin (who never called `pausePool`) must now call `unpausePool(pool)` to restore `pauseLevel` to `0`.
6. Until step 5 completes, all swap activity is halted and LP fees stop accruing — despite the protocol having "unpaused" the pool. [5](#0-4) [6](#0-5)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L392-403)
```text
  function protocolPausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0 && cur != 1) revert InvalidPauseTransition(cur, 2);
    IMetricOmmPoolFactoryActions(pool).setPause(2);
  }

  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L467-471)
```text
  function unpausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 1) revert InvalidPauseTransition(cur, 0);
    IMetricOmmPoolFactoryActions(pool).setPause(0);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L217-224)
```text
  function swap(
    address recipient,
    bool zeroForOne,
    int128 amountSpecified,
    uint128 priceLimitX64,
    bytes calldata callbackData,
    bytes calldata extensionData
  ) external whenNotPaused nonReentrant(PoolActions.SWAP) returns (int128, int128) {
```

**File:** metric-core/contracts/MetricOmmPool.sol (L643-645)
```text
  function _checkNotPaused() internal view {
    if (pauseLevel != 0) revert PoolPaused();
  }
```
