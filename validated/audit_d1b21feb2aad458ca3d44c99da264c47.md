### Title
Pool Admin Can Overwrite Pending Price Provider Proposal to Reset Timelock and Bait-and-Switch Oracle — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`proposePoolPriceProvider` contains no guard preventing a second call while a proposal is already pending. A pool admin can exploit this to publicly propose a favorable oracle to attract LP deposits, then silently overwrite the pending proposal with a different oracle just before the timelock expires, resetting the countdown and deceiving LPs who relied on the original proposal.

---

### Finding Description

`proposePoolPriceProvider` unconditionally overwrites `pendingPriceProvider[pool]` and `pendingPriceProviderExecuteAfter[pool]` on every call: [1](#0-0) 

There is no check of the form `if (pendingPriceProvider[pool] != address(0)) revert(...)`. The function only validates that the pool is not in immutable-provider mode and that the new provider's token pair matches: [2](#0-1) 

`executePoolPriceProviderUpdate` enforces the timelock against `pendingPriceProviderExecuteAfter[pool]` and executes whatever address is currently stored in `pendingPriceProvider[pool]`: [3](#0-2) 

Because the pending slot is a single address per pool with no "locked once ready" guard, a second `proposePoolPriceProvider` call atomically replaces both the target provider and the execution deadline.

There is no `cancelPoolPriceProviderProposal` function; the only way to clear the pending state is `executePoolPriceProviderUpdate` or overwriting via another `proposePoolPriceProvider` call. [4](#0-3) 

---

### Impact Explanation

The timelock exists so that LPs can observe a pending oracle change and exit before it takes effect. Overwriting the pending proposal:

1. **Bait-and-switch oracle**: Admin proposes oracle X (accurate, reputable) → LPs add liquidity → admin proposes oracle Y (stale, manipulable, or attacker-controlled) one block before the original deadline → timelock resets → oracle Y activates. LPs who deposited expecting oracle X are now priced by oracle Y, enabling bad-price execution or swap conservation failure.

2. **Indefinite timelock reset**: Admin repeatedly re-proposes (same or different provider) just before each deadline, preventing any oracle change from ever executing — or keeping LPs in a state of uncertainty about which oracle will ultimately be used.

Both outcomes break the admin-boundary invariant: the timelock is the only cap on oracle-change power for a semi-trusted pool admin, and this path bypasses it without any privileged escalation.

---

### Likelihood Explanation

The trigger is a single additional `proposePoolPriceProvider` call by the existing pool admin — no special role, no extra funds, no external dependency. The pool admin is explicitly semi-trusted (not fully trusted), so malicious behavior within the admin's own call surface is in scope. The attack is front-runnable and requires no mempool visibility by the victim.

---

### Recommendation

Reject a new proposal when one is already pending:

```solidity
function proposePoolPriceProvider(address pool, address newPriceProvider)
    external override nonReentrant onlyPoolAdmin(pool)
{
    // ADD: block overwrite of a live pending proposal
    if (pendingPriceProvider[pool] != address(0)) revert PriceProviderChangeAlreadyPending();
    ...
}
```

Alternatively, mirror the Berachef fix exactly: once `block.timestamp >= pendingPriceProviderExecuteAfter[pool]` (i.e., the proposal is ready to execute), disallow any new proposal until the current one is executed or explicitly cancelled via a separate `cancelPoolPriceProviderProposal` function.

---

### Proof of Concept

```
T=0      Admin calls proposePoolPriceProvider(pool, oracleX)
         → pendingPriceProvider[pool]            = oracleX
         → pendingPriceProviderExecuteAfter[pool] = T + timelock

T=0..TL  LPs observe PoolPriceProviderChangeProposed(oracleX) event,
         add liquidity expecting oracleX to become active.

T=TL-1   Admin calls proposePoolPriceProvider(pool, oracleY)
         → pendingPriceProvider[pool]            = oracleY   ← silently overwritten
         → pendingPriceProviderExecuteAfter[pool] = (TL-1) + timelock ← reset

T=2TL-1  Admin calls executePoolPriceProviderUpdate(pool)
         → oracleY is activated, not oracleX.
         LPs are now priced by oracleY, which may be stale,
         inverted, or attacker-controlled.
```

The root cause is in `MetricOmmPoolFactory.proposePoolPriceProvider` at lines 487–490: [5](#0-4)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L474-491)
```text
  function proposePoolPriceProvider(address pool, address newPriceProvider)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    PoolImmutables memory p = IMetricOmmPool(pool).getImmutables();
    uint256 timelock = priceProviderTimelock[pool];
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, newPriceProvider);

    address mutableProvider = PoolStateLibrary._slot3(pool);
    address current = mutableProvider != address(0) ? mutableProvider : p.immutablePriceProvider;
    uint256 executeAfter = block.timestamp + timelock;
    pendingPriceProvider[pool] = newPriceProvider;
    pendingPriceProviderExecuteAfter[pool] = executeAfter;
    emit PoolPriceProviderChangeProposed(pool, current, newPriceProvider, executeAfter);
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L494-506)
```text
  function executePoolPriceProviderUpdate(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    address pending = pendingPriceProvider[pool];
    if (pending == address(0)) revert NoPriceProviderChangeProposed();
    uint256 execAfter = pendingPriceProviderExecuteAfter[pool];
    // forge-lint: disable-next-line(block-timestamp) -- timelock enforcement legitimately relies on `block.timestamp`.
    if (block.timestamp < execAfter) revert PriceProviderTimelockNotElapsed(execAfter, block.timestamp);
    PoolImmutables memory p = IMetricOmmPool(pool).getImmutables();
    if (p.immutablePriceProvider != address(0)) revert PriceProviderImmutable();
    _validatePriceProvider(p.token0, p.token1, pending);
    IMetricOmmPoolFactoryActions(pool).setPriceProvider(pending);
    delete pendingPriceProvider[pool];
    delete pendingPriceProviderExecuteAfter[pool];
    emit PoolPriceProviderUpdated(pool, pending);
```

**File:** metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactoryPoolAdmin.sol (L54-58)
```text
  /// @notice Schedule price provider rotation for `pool` after timelock; reverts if the pool oracle is immutable.
  function proposePoolPriceProvider(address pool, address newPriceProvider) external;

  /// @notice Finalize scheduled provider update after `pendingPriceProviderExecuteAfter`.
  function executePoolPriceProviderUpdate(address pool) external;
```
