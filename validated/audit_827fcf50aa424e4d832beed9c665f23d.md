Looking at the actual code for `setPoolAdminFees` and the fee cap enforcement logic.

The code is clear. Here is the analysis:

---

### Title
Pool Admin Can Set Total `spreadFeeE6` Above `HARD_MAX_SPREAD_FEE_E6` via Missing Aggregate Cap Check — (`metric-core/contracts/MetricOmmPoolFactory.sol`)

### Summary

`setPoolAdminFees` validates only the admin component against `maxAdminSpreadFeeE6`, but never checks that `c.protocolSpreadFeeE6 + newAdminSpreadFeeE6 <= HARD_MAX_SPREAD_FEE_E6`. Because `maxAdminSpreadFeeE6` is initialized to `HARD_MAX_SPREAD_FEE_E6` (200,000) and can be set up to that same ceiling, a pool admin can push the pool's live `spreadFeeE6` well above the documented hard maximum whenever the pool carries any non-zero protocol fee component.

### Finding Description

`HARD_MAX_SPREAD_FEE_E6 = 200_000` is the absolute ceiling on total spread fee. [1](#0-0) 

At construction, `maxAdminSpreadFeeE6` is set equal to `HARD_MAX_SPREAD_FEE_E6`, meaning the admin component cap alone already equals the intended aggregate ceiling. [2](#0-1) 

`setPoolAdminFees` checks only the per-component bound:

```solidity
if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
```

then immediately computes and pushes the unchecked aggregate to the pool:

```solidity
IMetricOmmPoolFactoryActions(pool)
  .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, ...);
``` [3](#0-2) 

The pool's `setPoolFees` performs no cap check — it blindly stores whatever total the factory sends. [4](#0-3) 

**Concrete path (no trusted-owner action required after pool creation):**

1. Pool is created while `spreadProtocolFeeE6 = 100_000` (10%). Factory records `poolFeeConfig[pool].protocolSpreadFeeE6 = 100_000`, `adminSpreadFeeE6 = 0`. Pool's live `spreadFeeE6 = 100_000`.
2. Pool admin calls `setPoolAdminFees(pool, 200_000, 0)`.
   - Guard passes: `200_000 <= maxAdminSpreadFeeE6 (200_000)`.
   - `c.protocolSpreadFeeE6` is still `100_000` (unchanged in `poolFeeConfig`).
   - Factory calls `pool.setPoolFees(100_000 + 200_000, ...)` → pool stores `spreadFeeE6 = 300_000` (30%), 50% above `HARD_MAX_SPREAD_FEE_E6`.

The question's framing about the global `spreadProtocolFeeE6` being raised after creation is a red herring — the global default does not retroactively update `poolFeeConfig[pool].protocolSpreadFeeE6`. The vulnerability exists purely from the missing aggregate check in `setPoolAdminFees` and is reachable whenever a pool was created with any non-zero protocol fee.

### Impact Explanation

Every swap on the affected pool charges a spread fee above the documented hard maximum. Traders receive less output than the protocol guarantees as its absolute ceiling. This is a direct, per-swap loss of user funds proportional to the excess fee and swap volume. The pool admin is semi-trusted only within caps; exceeding the aggregate cap is an admin-boundary break.

### Likelihood Explanation

Any pool created with a non-zero protocol spread fee is vulnerable. The factory constructor starts `spreadProtocolFeeE6 = 0`, but the owner is expected to set a non-zero default before pools are created (the docs describe this as the normal operational flow). Once a pool exists with `protocolSpreadFeeE6 > 0`, the pool admin can trigger this at any time with a single transaction.

### Recommendation

Add an aggregate cap check inside `setPoolAdminFees` before pushing the total to the pool:

```solidity
if (c.protocolSpreadFeeE6 + newAdminSpreadFeeE6 > HARD_MAX_SPREAD_FEE_E6)
    revert AdminFeeTooHigh();
if (c.protocolNotionalFeeE8 + newAdminNotionalFeeE8 > HARD_MAX_NOTIONAL_FEE_E8)
    revert AdminFeeTooHigh();
```

Apply the same guard symmetrically in `setPoolProtocolFee` (owner path) to prevent the owner from pushing the protocol component so high that the admin component is effectively forced to zero.

### Proof of Concept

```solidity
// Foundry test sketch
function test_adminExceedsHardMaxSpreadFee() public {
    // Factory deployed; owner sets default protocol fee to 10%
    factory.setDefaultSpreadProtocolFeeE6(100_000);

    // Pool created: protocolSpreadFeeE6=100_000, adminSpreadFeeE6=0
    address pool = factory.createPool(params); // adminSpreadFeeE6=0 in params

    // Pool admin sets admin fee to HARD_MAX (200_000)
    vm.prank(poolAdmin);
    factory.setPoolAdminFees(pool, 200_000, 0);

    // Pool's live spreadFeeE6 is now 300_000 — 50% above HARD_MAX_SPREAD_FEE_E6
    assertGt(IMetricOmmPool(pool).spreadFeeE6(), 200_000);
}
```

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L44-45)
```text
  uint24 internal constant HARD_MAX_SPREAD_FEE_E6 = 200_000;
  uint24 internal constant HARD_MAX_NOTIONAL_FEE_E8 = 1_000_000;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L105-108)
```text
    maxProtocolSpreadFeeE6 = HARD_MAX_SPREAD_FEE_E6;
    maxAdminSpreadFeeE6 = HARD_MAX_SPREAD_FEE_E6;
    maxProtocolNotionalFeeE8 = HARD_MAX_NOTIONAL_FEE_E8;
    maxAdminNotionalFeeE8 = HARD_MAX_NOTIONAL_FEE_E8;
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L414-432)
```text
    if (newAdminSpreadFeeE6 > maxAdminSpreadFeeE6) revert AdminFeeTooHigh();
    if (newAdminNotionalFeeE8 > maxAdminNotionalFeeE8) revert AdminFeeTooHigh();

    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );

    c.adminSpreadFeeE6 = newAdminSpreadFeeE6;
    c.adminNotionalFeeE8 = newAdminNotionalFeeE8;
    poolFeeConfig[pool] = c;

    IMetricOmmPoolFactoryActions(pool)
      .setPoolFees(c.protocolSpreadFeeE6 + c.adminSpreadFeeE6, c.protocolNotionalFeeE8 + c.adminNotionalFeeE8);
```

**File:** metric-core/contracts/MetricOmmPool.sol (L437-452)
```text
  function setPoolFees(uint24 newSpreadFeeE6, uint24 newNotionalFeeE8)
    external
    onlyFactory
    nonReentrant(PoolActions.SET_POOL_FEES)
  {
    unchecked {
      if (newSpreadFeeE6 != spreadFeeE6) {
        spreadFeeE6 = newSpreadFeeE6;
        emit SpreadFeeUpdated(newSpreadFeeE6);
      }
      if (newNotionalFeeE8 != notionalFeeE8) {
        notionalFeeE8 = newNotionalFeeE8;
        emit NotionalFeeUpdated(newNotionalFeeE8);
      }
    }
  }
```
