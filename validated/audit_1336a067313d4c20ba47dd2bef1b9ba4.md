### Title
`proposePoolPriceProvider` Silently Overwrites Pending Proposal Without Existence Check, Enabling Timelock-Reset Bait-and-Switch Oracle Attack — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

---

### Summary

`proposePoolPriceProvider` writes directly to `pendingPriceProvider[pool]` and `pendingPriceProviderExecuteAfter[pool]` without checking whether a proposal is already pending. Because there is also no cancel function for price-provider proposals (unlike admin transfer, which has `cancelPoolAdminTransfer`), the only way to "cancel" is to re-propose — which silently resets the timelock. A pool admin can exploit this to execute a bait-and-switch: announce a legitimate oracle, let LPs decide to stay, then swap in a malicious oracle address just before the first timelock elapses, restarting the clock with a provider that delivers stale, inverted, or unbounded bid/ask prices.

---

### Finding Description

In `MetricOmmPoolFactory.proposePoolPriceProvider` (lines 474–491), the function performs no guard on the existing pending state:

```solidity
pendingPriceProvider[pool] = newPriceProvider;          // unconditional overwrite
pendingPriceProviderExecuteAfter[pool] = executeAfter;  // timelock reset
``` [1](#0-0) 

There is no `if (pendingPriceProvider[pool] != address(0)) revert ...` guard, and the interface exposes no `cancelPriceProviderProposal` function. [2](#0-1) 

By contrast, the admin-transfer flow has an explicit `cancelPoolAdminTransfer` that emits `PoolAdminTransferCancelled`, giving observers a clear signal. [3](#0-2) 

The price-provider flow has no equivalent. The only observable signal of a swap is a second `PoolPriceProviderChangeProposed` event, which off-chain monitors may miss or misinterpret as a routine update rather than a replacement of a previously announced provider.

---

### Impact Explanation

After `executePoolPriceProviderUpdate` applies the pending provider, the pool reads bid/ask exclusively from that address on every swap: [4](#0-3) 

If the executed provider is malicious (stale, inverted, or unbounded prices), every subsequent swap executes at a wrong price. Traders receive more tokens than the oracle curve permits (swap conservation failure), or LPs are drained because the pool settles at a price that does not reflect fair value. This maps directly to the allowed impacts: **bad-price execution** and **pool insolvency** (balances fail to cover LP claims after adversarial swaps at manipulated prices).

---

### Likelihood Explanation

The trigger requires only the pool admin — a semi-trusted role that is explicitly in scope ("pool admin is semi-trusted only inside caps and timelocks; look for bypasses in … provider proposals"). No external attacker capability is needed. The admin calls `proposePoolPriceProvider` twice: once with a legitimate address to build LP confidence, and once with a malicious address to reset the timelock. Both calls are valid on-chain operations that pass all existing guards (`_validatePriceProvider` only checks token pair matching, not provider price quality). [5](#0-4) 

---

### Recommendation

Add an existence check at the top of `proposePoolPriceProvider` that reverts if a proposal is already pending, mirroring the pattern used in `executePoolPriceProviderUpdate`:

```solidity
if (pendingPriceProvider[pool] != address(0)) revert PriceProviderProposalAlreadyPending();
```

Additionally, add a dedicated `cancelPoolPriceProviderProposal` function (analogous to `cancelPoolAdminTransfer`) that emits a distinct `PoolPriceProviderChangeCancelled` event, so off-chain monitors receive an unambiguous signal when a proposal is withdrawn.

---

### Proof of Concept

```solidity
// 1. Admin proposes legitimate oracle A — LPs observe and decide to stay.
vm.prank(admin);
factory.proposePoolPriceProvider(pool, address(legitimateOracle));

// 2. Just before timelock elapses, admin silently replaces with malicious oracle B.
//    No revert; pendingPriceProvider and pendingPriceProviderExecuteAfter are overwritten.
vm.prank(admin);
factory.proposePoolPriceProvider(pool, address(maliciousOracle));
// pendingPriceProviderExecuteAfter[pool] is now block.timestamp + timelock (reset)

// 3. After the new timelock elapses, admin executes — malicious oracle is now active.
vm.warp(block.timestamp + timelock);
vm.prank(admin);
factory.executePoolPriceProviderUpdate(pool);
// All subsequent swaps price against maliciousOracle's stale/inverted bid-ask.
``` [6](#0-5)

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

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L529-534)
```text
  function cancelPoolAdminTransfer(address pool) external override nonReentrant onlyPoolAdmin(pool) {
    address pending = pendingPoolAdmin[pool];
    if (pending == address(0)) revert NoPendingPoolAdminTransfer();
    delete pendingPoolAdmin[pool];
    emit PoolAdminTransferCancelled(pool, pending);
  }
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

**File:** metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactoryPoolAdmin.sol (L52-58)
```text
  // --- Price provider (mutable oracle only) ---

  /// @notice Schedule price provider rotation for `pool` after timelock; reverts if the pool oracle is immutable.
  function proposePoolPriceProvider(address pool, address newPriceProvider) external;

  /// @notice Finalize scheduled provider update after `pendingPriceProviderExecuteAfter`.
  function executePoolPriceProviderUpdate(address pool) external;
```
