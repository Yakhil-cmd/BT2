### Title
First pool created by factory is permanently misidentified as non-canonical by `isPool` due to zero-index collision — (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary
`MetricOmmPoolFactory.isPool` uses `poolToIdx[pool] != 0` as its canonical-pool sentinel. Because `nextPoolIdx` is a default-zero `uint256`, the very first pool created receives index `0`, making `poolToIdx[firstPool] == 0`, which is indistinguishable from an unregistered address. `isPool` permanently returns `false` for the first pool, breaking the registry invariant the rest of the system relies on.

### Finding Description

`nextPoolIdx` is an uninitialized `uint256` storage variable, so it starts at `0`. In `createPool`:

```solidity
uint256 poolIdx = nextPoolIdx;   // == 0 for the first pool
nextPoolIdx++;
idxToPool[poolIdx] = pool;       // idxToPool[0] = firstPool
poolToIdx[pool] = poolIdx;       // poolToIdx[firstPool] = 0
``` [1](#0-0) 

The canonical-pool check is:

```solidity
function isPool(address pool) external view override returns (bool) {
    return poolToIdx[pool] != 0;
}
``` [2](#0-1) 

For the first pool, `poolToIdx[firstPool] == 0`, so `isPool(firstPool)` returns `false` — the same value returned for any address that was never registered. The pool is fully deployed and its fee config, admin, and price provider are all correctly stored, but the registry identity is permanently corrupted.

The inconsistency is observable: `idxToPool(0)` returns the first pool's address, yet `isPool(firstPool)` returns `false` and `poolToIdx(firstPool)` returns `0`.

### Impact Explanation

Any router, quoter, or off-chain system that gates access on `isPool` will treat the first factory pool as non-canonical and reject it. This makes the first pool's swap and liquidity flows unusable through canonical periphery contracts, matching the "broken core pool functionality / unusable swap/liquidity flows" impact class. The pool's internal state is correct, but its registry identity is permanently broken with no recovery path — the factory has no function to re-register or re-index an existing pool.

### Likelihood Explanation

The trigger is the very first call to `createPool` on any freshly deployed factory, which is a permissionless, expected, and inevitable operation. Every deployment of the factory will produce exactly one permanently misidentified pool. Likelihood is certain.

### Recommendation

Initialize `nextPoolIdx` to `1` so that the zero value of `poolToIdx` unambiguously means "not registered":

```solidity
uint256 public nextPoolIdx = 1;
```

Alternatively, maintain a separate `mapping(address => bool) public isRegisteredPool` that is set to `true` in `createPool` and use that in `isPool`.

### Proof of Concept

```solidity
// After factory.setPoolDeployer(deployer):
address firstPool = factory.createPool(params);

// Registry is inconsistent:
assertEq(factory.idxToPool(0), firstPool);          // firstPool IS at index 0
assertFalse(factory.isPool(firstPool));              // but isPool returns false
assertEq(factory.poolToIdx(firstPool), 0);           // same sentinel as unregistered

// Any router that does:
//   require(factory.isPool(pool), "not canonical");
// will revert for firstPool, making it permanently unusable through canonical periphery.
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
