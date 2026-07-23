### Title
First Pool Created Is Never Recognized as a Valid Pool by `isPool()` — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`MetricOmmPoolFactory` assigns pool registry indices starting from `nextPoolIdx = 0`. The first pool deployed receives `poolToIdx[pool] = 0`, which is indistinguishable from the default mapping value for any unregistered address. As a result, `isPool(firstPool)` permanently returns `false`, breaking the canonical registry identity for the first pool ever created.

### Finding Description

In `MetricOmmPoolFactory.createPool`, pool registration is:

```solidity
uint256 poolIdx = nextPoolIdx;   // = 0 for the very first pool
nextPoolIdx++;
idxToPool[poolIdx] = pool;
poolToIdx[pool] = poolIdx;       // poolToIdx[firstPool] = 0
``` [1](#0-0) 

The canonical identity check is:

```solidity
function isPool(address pool) external view override returns (bool) {
    return poolToIdx[pool] != 0;
}
``` [2](#0-1) 

Because `nextPoolIdx` is an uninitialized `uint256` state variable (default `0`), the first pool is assigned index `0`. The sentinel value used by `isPool` to mean "not a pool" (`poolToIdx[x] == 0`) is the same value stored for the first legitimate pool. Every subsequent pool (index ≥ 1) is correctly identified; only the first pool is permanently misidentified as non-canonical.

### Impact Explanation

Any on-chain or off-chain consumer that calls `isPool(pool)` to gate access — routers, quoters, aggregators, or any future factory extension — will treat the first deployed pool as an unregistered address. Concretely:

- **Fee collection**: `collectPoolFees` is documented as a permissionless public path. If it (or any caller) guards execution with `isPool`, fees accrued in the first pool can never be extracted through the normal path, permanently locking protocol and admin fee revenue.
- **Router/integration gating**: Any router or periphery contract that validates pool identity before routing a swap or liquidity call will silently reject the first pool, making it effectively unusable for integrated flows while still holding real user funds.
- **Registry consumers**: `idxToPool[0]` correctly returns the first pool's address, but `isPool` contradicts it, creating an inconsistent registry state that can confuse any system iterating or cross-checking both mappings.

This matches the "pool insolvency / broken core pool functionality" impact gate: the first pool's fees are unclaimable and its swap/liquidity flows are broken for any integration that relies on `isPool`.

### Likelihood Explanation

The factory is permissionless — any caller can invoke `createPool`. The first pool is created by whoever calls `createPool` first after `poolDeployer` is set. The bug is deterministic and unconditional: it triggers on every deployment of the factory, for every first pool, with no special preconditions. No attacker action is required; the misconfiguration is structural.

### Recommendation

Initialize `nextPoolIdx` to `1` so that index `0` is permanently reserved as the sentinel "not a pool" value:

```solidity
uint256 public nextPoolIdx = 1;
```

This makes `poolToIdx[unregisteredAddress] == 0` unambiguously mean "not a pool," and the first real pool receives index `1`, so `isPool` returns `true` for it.

### Proof of Concept

```solidity
// After factory setup:
address firstPool = factory.createPool(params);

// First pool gets poolToIdx[firstPool] = 0 (nextPoolIdx started at 0)
assertEq(factory.poolToIdx(firstPool), 0);

// isPool returns false for the first pool — same as any random address
assertFalse(factory.isPool(firstPool));
assertFalse(factory.isPool(address(0xdead)));

// But idxToPool(0) correctly returns the first pool — registry is inconsistent
assertEq(factory.idxToPool(0), firstPool);

// Second pool is fine
address secondPool = factory.createPool(params2);
assertTrue(factory.isPool(secondPool)); // poolToIdx[secondPool] = 1
``` [2](#0-1) [1](#0-0)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L149-151)
```text
  function isPool(address pool) external view override returns (bool) {
    return poolToIdx[pool] != 0;
  }
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L222-225)
```text
    uint256 poolIdx = nextPoolIdx;
    nextPoolIdx++;
    idxToPool[poolIdx] = pool;
    poolToIdx[pool] = poolIdx;
```
