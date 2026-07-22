### Title
`setPoolAdminFeeDestination` Redirects Already-Accrued Admin Fees Without Prior Collection - (File: metric-core/contracts/MetricOmmPoolFactory.sol)

### Summary

`setPoolAdminFeeDestination` updates `poolAdminFeeDestination[pool]` immediately without first calling `collectFees`, allowing a pool admin to silently redirect all accrued-but-uncollected admin spread fees to a new address. This is the direct analog of the `LineOfCredit.close(id)` bug: a state-change that should settle owed fees first does not call the settlement function, causing fees to flow to the wrong recipient.

### Finding Description

Every other fee-configuration mutator in `MetricOmmPoolFactory` that touches fee parameters calls `collectFees` on the pool **before** applying the change, so that accrued fees are settled at the old rates/destination:

- `setPoolAdminFees` (lines 418–425): calls `collectFees` first, then updates `poolFeeConfig`.
- `setPoolProtocolFee` (lines 328–335): calls `collectFees` first, then updates `poolFeeConfig`.

`setPoolAdminFeeDestination` breaks this invariant:

```solidity
// metric-core/contracts/MetricOmmPoolFactory.sol
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;   // ← no collectFees first
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

The pool's spread-fee balance is not explicitly tracked per-recipient; it is the implicit surplus:

```
surplus0Scaled = balance0() * TOKEN_0_SCALE_MULTIPLIER
               - binTotals.scaledToken0
               - notionalFeeToken0Scaled
```

This surplus accumulates continuously as swaps execute. When `collectPoolFees` (or any fee-collecting path) is eventually called, **all** of that surplus is distributed to whoever `poolAdminFeeDestination[pool]` is **at that moment**, not to whoever it was when the fees accrued.

### Impact Explanation

A pool admin calls `setPoolAdminFeeDestination(pool, attackerAddress)` after a period of heavy swap activity. All spread fees that accrued while the old destination was set are now sent to `attackerAddress` on the next `collectPoolFees` call. The old destination (e.g., a DAO treasury, a previous admin's multisig, or a protocol-designated address) receives nothing for the period it was the rightful recipient. The loss is bounded by the total accrued surplus at the time of the destination change, which can be substantial in a high-volume pool.

This is a direct loss of protocol/admin fee revenue — an allowed impact under the contest gate ("Critical/High/Medium direct loss of … protocol fees … above Sherlock thresholds" and "Admin-boundary break: … fee collection destinations").

### Likelihood Explanation

The pool admin is semi-trusted and has explicit authority to call `setPoolAdminFeeDestination`. No timelock, cap, or guard prevents this call. The admin need only call it before the next `collectPoolFees` invocation. Since `collectPoolFees` is permissionless and can be called by anyone, the admin can front-run it or simply act before any keeper does. The inconsistency with `setPoolAdminFees` (which does collect first) confirms this is an unintended omission rather than a deliberate design choice.

### Recommendation

Add a `collectFees` call at the start of `setPoolAdminFeeDestination`, mirroring the pattern used by `setPoolAdminFees` and `setPoolProtocolFee`:

```solidity
function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external override nonReentrant onlyPoolAdmin(pool)
{
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    // Settle accrued fees to the OLD destination before switching
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool).collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]   // old destination
    );
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
}
```

### Proof of Concept

1. Deploy pool with `adminFeeDestination = treasury`.
2. LPs add liquidity; swaps execute, accumulating spread-fee surplus in the pool balance.
3. Pool admin calls `setPoolAdminFeeDestination(pool, attackerWallet)` — no fees collected.
4. Anyone calls `collectPoolFees(pool)`.
5. `collectFees` computes `surplus = balance - binTotals - notionalFees` and sends the admin share to `attackerWallet`.
6. `treasury` receives zero despite being the rightful recipient for all fees accrued in steps 1–2.

**Corrupted value:** `poolAdminFeeDestination[pool]` is updated before the accrued surplus is settled, causing the entire admin spread-fee surplus to flow to the new address instead of the old one.

---

**Relevant code locations:**

`setPoolAdminFeeDestination` — no `collectFees` call: [1](#0-0) 

`setPoolAdminFees` — correct pattern (collects first): [2](#0-1) 

`setPoolProtocolFee` — correct pattern (collects first): [3](#0-2) 

`collectFees` surplus computation (the value that gets misdirected): [4](#0-3)

### Citations

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L327-335)
```text
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L417-425)
```text
    PoolFeeConfig memory c = poolFeeConfig[pool];
    IMetricOmmPoolCollectFees(pool)
      .collectFees(
        c.protocolSpreadFeeE6,
        c.adminSpreadFeeE6,
        c.protocolNotionalFeeE8,
        c.adminNotionalFeeE8,
        poolAdminFeeDestination[pool]
      );
```

**File:** metric-core/contracts/MetricOmmPoolFactory.sol (L438-447)
```text
  function setPoolAdminFeeDestination(address pool, address newAdminFeeDestination)
    external
    override
    nonReentrant
    onlyPoolAdmin(pool)
  {
    if (newAdminFeeDestination == address(0)) revert InvalidAdminFeeDestination();
    poolAdminFeeDestination[pool] = newAdminFeeDestination;
    emit PoolAdminFeeDestinationUpdated(pool, newAdminFeeDestination);
  }
```

**File:** metric-core/contracts/MetricOmmPool.sol (L385-388)
```text
    uint256 surplus0Scaled =
      balance0() * TOKEN_0_SCALE_MULTIPLIER - uint256(binTotals.scaledToken0) - notionalFee0AmountScaled;
    uint256 surplus1Scaled =
      balance1() * TOKEN_1_SCALE_MULTIPLIER - uint256(binTotals.scaledToken1) - notionalFee1AmountScaled;
```
