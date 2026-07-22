### Title
Pool Admin Can Permanently Block Swap Functionality With No Protocol Override Path — (File: `metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary
The pool admin (`poolAdmin[pool]`) can call `pausePool` to set pause level 1, permanently blocking all swaps. The protocol owner's only unpause function, `protocolUnpausePool`, is hard-coded to transition `2 → 1` only — it cannot reach level 0. There is no factory function that lets the protocol owner force-resume a pool to level 0, and no function that lets the protocol owner replace `poolAdmin[pool]`. A compromised or malicious pool admin can therefore permanently disable swap functionality with no on-chain recovery path.

### Finding Description

The pause state machine in `MetricOmmPoolFactory` is:

| Transition | Caller | Function |
|---|---|---|
| 0 → 1 | Pool admin | `pausePool` |
| 1 → 0 | Pool admin | `unpausePool` |
| 0 → 2 or 1 → 2 | Protocol owner | `protocolPausePool` |
| 2 → 1 **only** | Protocol owner | `protocolUnpausePool` |

`pausePool` requires only `onlyPoolAdmin` with no timelock and no cap on pause duration: [1](#0-0) 

`protocolUnpausePool` is hard-coded to transition to level 1, not level 0: [2](#0-1) 

The pool's `_checkNotPaused` reverts on any non-zero pause level, so both level 1 and level 2 block swaps equally: [3](#0-2) 

`swap` carries `whenNotPaused`; `addLiquidity` and `removeLiquidity` do not: [4](#0-3) 

The protocol owner has no function to set `poolAdmin[pool]` directly, so it cannot replace a malicious admin. The only admin-transfer path is `proposePoolAdminTransfer` + `acceptPoolAdmin`, both of which require the current admin to initiate: [5](#0-4) 

The design intent is documented explicitly — "Intentional design: after a protocol pause, the pool admin must explicitly call `unpausePool` to resume trading. The owner cannot bypass admin consent to reach level 0": [6](#0-5) 

This means the protocol owner's only available response to a malicious admin pause is to escalate to level 2 (`protocolPausePool`) and then back to level 1 (`protocolUnpausePool`) — which leaves the pool in the same admin-paused state. The protocol is stuck in a loop with no exit.

### Impact Explanation

Swaps are permanently disabled for any pool whose admin is compromised or malicious. `removeLiquidity` is not gated by pause, so LP principal is not directly at risk of loss. However, the core swap flow — the primary purpose of an AMM pool — is rendered permanently unusable. Protocol fees from swaps cease to accrue. LPs cannot trade out of positions via the pool. This satisfies the "unusable swap/liquidity flows" criterion in the allowed impact gate.

### Likelihood Explanation

The pool admin is documented as a single address (`poolAdmin[pool]`) that may be an EOA. The documentation itself warns: "use a multisig or explicit admin contract, not an EOA unless you accept key risk." A single EOA admin is a realistic deployment scenario. Key compromise, insider threat, or social engineering of a single admin key is a plausible trigger. No special preconditions are required beyond the admin being malicious or compromised — the pause call itself is a single transaction with no setup. [7](#0-6) 

### Recommendation

Add a protocol-owner escape hatch that can force-resume a pool to level 0 after a minimum delay (e.g., a timelock-gated `protocolForceUnpausePool` that transitions any level → 0 after N days without admin action). Alternatively, give the protocol owner the ability to replace `poolAdmin[pool]` directly, bypassing the two-step admin-transfer flow, so a non-responsive or malicious admin can be replaced. Either mechanism preserves the intended admin-first design for normal operations while providing a recovery path when the admin is unavailable.

### Proof of Concept

```solidity
// 1. Admin pauses the pool (level 0 → 1)
vm.prank(admin);
factory.pausePool(pool);
assertEq(_pauseLevel(pool), 1);

// 2. Protocol owner tries to force-resume — can only go 1 → 2
factory.protocolPausePool(pool);
assertEq(_pauseLevel(pool), 2);

// 3. Protocol owner unpauses — lands at 1, not 0
factory.protocolUnpausePool(pool);
assertEq(_pauseLevel(pool), 1); // still admin-paused

// 4. Swap is still blocked
vm.expectRevert(IMetricOmmPoolActions.PoolPaused.selector);
pool.swap(...);

// 5. Protocol owner has no further recourse — no function exists to go 1 → 0
//    without the admin's cooperation. Pool is permanently paused.
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L398-403)
```text
  /// @inheritdoc IMetricOmmPoolFactoryOwner
  function protocolUnpausePool(address pool) external override nonReentrant onlyOwner {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 2) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L459-464)
```text
  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function pausePool(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    (uint8 cur,,,,,) = PoolStateLibrary._slot0(pool);
    if (cur != 0) revert InvalidPauseTransition(cur, 1);
    IMetricOmmPoolFactoryActions(pool).setPause(1);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L510-526)
```text
  function proposePoolAdminTransfer(address pool, address newAdmin) external override nonReentrant onlyPoolAdmin(pool) {
    if (newAdmin == address(0)) revert InvalidAdmin();
    if (newAdmin == poolAdmin[pool]) revert InvalidAdmin();
    pendingPoolAdmin[pool] = newAdmin;
    emit PoolAdminTransferProposed(pool, poolAdmin[pool], newAdmin);
  }

  /// @inheritdoc IMetricOmmPoolFactoryPoolAdmin
  function acceptPoolAdmin(address pool) external override nonReentrant {
    address pending = pendingPoolAdmin[pool];
    if (pending == address(0)) revert NoPendingPoolAdminTransfer();
    if (msg.sender != pending) revert NotPendingPoolAdmin(pool, msg.sender, pending);
    address previousAdmin = poolAdmin[pool];
    poolAdmin[pool] = pending;
    delete pendingPoolAdmin[pool];
    emit PoolAdminTransferred(pool, previousAdmin, pending);
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

**File:** metric-core/docs/POOL_CONFIGURATION_AND_MANAGEMENT.md (L47-50)
```markdown
| Parameter                 | Role                                                                                                                                                             | Guidelines                                                                                                                                |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **`admin`**               | Becomes **`poolAdmin[pool]`** on the factory; this address controls pool-scoped admin actions (fees, pause L1, oracle proposal/execute, admin transfer).         | Non-zero; use a multisig or explicit admin contract, not an EOA unless you accept key risk.                                               |
| **`adminSpreadFeeE6`**    | **Admin spread fee** component in **E6** (`1e6 = 100%`). **Protocol spread** is the factory’s current **`spreadProtocolFeeE6`** (not in `PoolParameters`).       | Must be ≤ factory **`maxAdminSpreadFeeE6`**. Total spread on the pool is `spreadProtocolFeeE6 + adminSpreadFeeE6` at deploy time.         |
```

**File:** metric-core/docs/POOL_CONFIGURATION_AND_MANAGEMENT.md (L199-202)
```markdown
| ------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`protocolPausePool(pool)`**   | Sets pause level **2** from **0** or **1**. | Strongest halt (e.g. security event). Swaps remain disabled at L2.                                                                                                                   |
| **`protocolUnpausePool(pool)`** | Moves **2 → 1** (not to **0**).             | **Intentional design:** after a protocol pause, the pool admin must explicitly call **`unpausePool`** to resume trading. The owner cannot bypass admin consent to reach level **0**. |

```
