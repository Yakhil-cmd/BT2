The vulnerability is real. Here is the complete analysis:

---

### Title
Pending price provider proposal survives admin handover, allowing new admin to execute a change they never proposed — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`acceptPoolAdmin` transfers the pool admin role but does not clear `pendingPriceProvider[pool]` or `pendingPriceProviderExecuteAfter[pool]`. A new admin who accepts the role inherits any in-flight provider proposal made by the previous admin and can execute it after the timelock elapses, activating a price provider they never vetted or proposed.

### Finding Description

`acceptPoolAdmin` only updates `poolAdmin[pool]` and deletes `pendingPoolAdmin[pool]`: [1](#0-0) 

Neither `pendingPriceProvider[pool]` nor `pendingPriceProviderExecuteAfter[pool]` are touched. These mappings are declared independently: [2](#0-1) 

`executePoolPriceProviderUpdate` only checks that the caller is the current pool admin and that the timelock has elapsed — it does not verify that the current admin was the one who proposed the pending change: [3](#0-2) 

Attack sequence:
1. Old admin calls `proposePoolPriceProvider(pool, maliciousProvider)` → `pendingPriceProvider[pool] = maliciousProvider`, timelock starts.
2. Old admin calls `proposePoolAdminTransfer(pool, newAdmin)`.
3. New admin calls `acceptPoolAdmin(pool)` → becomes pool admin; `pendingPriceProvider[pool]` is **not** cleared.
4. After `pendingPriceProviderExecuteAfter[pool]` elapses, new admin calls `executePoolPriceProviderUpdate(pool)` → `maliciousProvider` is activated.

There is no `cancelPriceProviderProposal` function. The only way for the new admin to neutralize the inherited proposal is to call `proposePoolPriceProvider` with a different address, which resets the timelock but does not cancel the old one atomically. [4](#0-3) 

### Impact Explanation

If the inherited provider returns manipulated or stale bid/ask prices, every subsequent swap executes at a bad price. Traders receive more output than the correct oracle permits (swap conservation failure) or the pool receives less input than owed, directly draining pool reserves. This falls squarely within the contest's "bad-price execution" and "admin-boundary break" impact categories.

### Likelihood Explanation

Requires a semi-trusted old admin to propose a malicious provider before transferring the role, and the new admin to call `executePoolPriceProviderUpdate` without first auditing `pendingPriceProvider[pool]`. Automated governance bots or multisig scripts that execute all pending factory actions on role acceptance make step 4 realistic without deliberate intent by the new admin.

### Recommendation

In `acceptPoolAdmin`, clear the inherited pending provider state:

```solidity
delete pendingPriceProvider[pool];
delete pendingPriceProviderExecuteAfter[pool];
```

Alternatively, add a dedicated `cancelPriceProviderProposal` function callable by the current pool admin, and document that incoming admins must audit and cancel any pending proposals before accepting.

### Proof of Concept

```solidity
// 1. Old admin proposes a malicious provider
vm.prank(oldAdmin);
factory.proposePoolPriceProvider(pool, address(maliciousProvider));

// 2. Old admin initiates transfer to newAdmin
vm.prank(oldAdmin);
factory.proposePoolAdminTransfer(pool, newAdmin);

// 3. New admin accepts — pendingPriceProvider is NOT cleared
vm.prank(newAdmin);
factory.acceptPoolAdmin(pool);
assertEq(factory.pendingPriceProvider(pool), address(maliciousProvider)); // still set

// 4. Warp past timelock
vm.warp(block.timestamp + factory.priceProviderTimelock(pool) + 1);

// 5. New admin executes old admin's proposal
vm.prank(newAdmin);
factory.executePoolPriceProviderUpdate(pool); // succeeds with old admin's provider

// Pool now uses maliciousProvider for all swap pricing
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L77-80)
```text
  mapping(address => address) public override pendingPriceProvider;

  /// @inheritdoc IMetricOmmPoolFactory
  mapping(address => uint256) public override pendingPriceProviderExecuteAfter;
```

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L494-507)
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
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L518-526)
```text
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
