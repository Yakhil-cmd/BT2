### Title
Block-Number-Based Velocity Guard Is Unreliable on Variable-Block-Time Chains, Allowing Manipulated Oracle Prices to Bypass the Guard — (File: `metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol`)

---

### Summary

`PriceVelocityGuardExtension` measures elapsed time between price updates using `block.number` rather than `block.timestamp`. Because block production rates are not fixed — especially on L2 chains (Arbitrum, Optimism, Base) where blocks can be produced every ~0.25 s — the guard's effective per-real-time-unit allowance varies dramatically across chains and over time, making it far more permissive than the pool admin intends and potentially allowing a manipulated oracle price to reach the pool.

---

### Finding Description

`PriceVelocityGuardExtension.beforeSwap` enforces the invariant:

```
changeE18² ≤ maxChangePerBlockE18² × (1 + blockDiff)
```

where `blockDiff = block.number - s.lastUpdateBlock`. [1](#0-0) 

Both the "last seen" block and the current block are recorded via `block.number`: [2](#0-1) [3](#0-2) 

The NatSpec documents the intent as "caps how fast the provided price can move **between blocks**", and the admin-facing setter is `setMaxChangePerBlock`. [4](#0-3) 

The problem: `block.number` is not a reliable proxy for elapsed wall-clock time.

| Chain | Avg block time | Blocks per real minute |
|---|---|---|
| Ethereum mainnet | ~12 s | ~5 |
| Arbitrum One | ~0.25 s | ~240 |
| Optimism / Base | ~2 s | ~30 |

If a pool admin sets `maxChangePerBlockE18` calibrated for Ethereum (5 blocks/min), the same value on Arbitrum (240 blocks/min) makes `allowedSq` grow **48× faster per real minute** (`sqrt(241)/sqrt(6) ≈ 6.3×` in linear terms). A price move that should be blocked within one real minute is permitted because `blockDiff` is already 240 instead of 5.

Additionally, even on a single chain, block times are not constant. Arbitrum's block cadence has changed historically, and any future change silently recalibrates the guard without any on-chain signal.

---

### Impact Explanation

The velocity guard is the pool's last line of defense against a rapidly-moving (potentially manipulated) oracle price reaching `beforeSwap`. If the guard is effectively disabled by fast block production:

- A compromised or flash-manipulated oracle can push a large price jump through `beforeSwap` in a single real-world second.
- The pool executes swaps at the manipulated bid/ask, causing traders to receive more tokens than the true oracle price permits, or the pool to receive fewer input tokens than owed.
- LPs bear the resulting shortfall — a direct loss of principal.

This matches the allowed impact: **bad-price execution** and **direct loss of LP assets**.

---

### Likelihood Explanation

- Metric OMM is explicitly designed for multi-chain deployment (the repo contains L2-specific oracle contracts such as `PriceProviderL2.sol`).
- Pool admins calibrating `maxChangePerBlockE18` will naturally think in "per block" units as the parameter name suggests, without necessarily accounting for the chain's actual block cadence.
- No on-chain check enforces that the parameter is chain-aware; the factory and pool accept any `uint64` value.
- The guard is an optional but production-ready extension (`metric-periphery/contracts/extensions/`), so real pools are expected to use it.

---

### Recommendation

Replace `block.number` with `block.timestamp` throughout `PriceVelocityGuardExtension`:

1. Rename `lastUpdateBlock` → `lastUpdateTimestamp` (store `block.timestamp`).
2. Rename `maxChangePerBlockE18` → `maxChangePerSecondE18` (or per-millisecond).
3. Compute `timeDiff = block.timestamp - s.lastUpdateTimestamp` and use it in the allowed-change formula.
4. Update the setter, interface, events, and NatSpec accordingly.

`block.timestamp` has a small miner-manipulation window (~15 s on Ethereum, negligible on L2 sequencers), which is acceptable for a velocity guard whose purpose is to catch large, rapid price swings — not sub-second precision.

---

### Proof of Concept

**Setup**: Arbitrum One. Pool uses `PriceVelocityGuardExtension` with `maxChangePerBlockE18 = 0.01e18` (1% per block), calibrated assuming ~12 s Ethereum blocks (i.e., the admin intends to allow at most ~5% price movement per real minute via `sqrt(1+5) ≈ 2.45`).

**Attack**:
1. Oracle price is at `P`.
2. Attacker waits 60 real seconds. On Arbitrum, ~240 blocks pass.
3. `allowedSq = (0.01e18)² × (1 + 240) = 1e34 × 241`.
4. `sqrt(allowedSq) / 1e18 ≈ 155%` — the guard now permits a **155% price move** in one real minute.
5. Attacker pushes a manipulated oracle price 50% above `P` (well within the 155% window).
6. `beforeSwap` passes. The pool executes swaps at the manipulated price, overpaying traders from LP reserves.

On Ethereum with the same parameter, the same 60-second window only permits `sqrt(1+5) × 1% ≈ 2.45%` — the 50% move would have been correctly rejected. [5](#0-4)

### Citations

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L10-18)
```text
/// @notice Caps how fast the provided price can move between blocks, per pool.
/// @dev This extension allows the pool admin to increase security of the pool by limiting price
///      manipulation through velocity constraints. However, it assumes that the pool admin is not
///      an adversary and acts to optimize pool profitability. The pool admin must be trusted.
///
///      Allowed deviation scales as `maxChangePerBlockE18 * sqrt(1 + blockDifference)`.
///      Comparison is performed on squares to avoid an on-chain sqrt:
///        changeE18^2 <= maxChangePerBlockE18^2 * (1 + blockDiff)
///      where 1e18 = 100% (full unit).
```

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L32-33)
```text
    s.lastUpdateBlock = uint64(block.number);
    emit LastMidPriceUpdated(pool_, newLastMidPriceX64);
```

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L55-74)
```text
    uint64 prevBlock = s.lastUpdateBlock;

    s.lastMidPriceX64 = midPrice;
    s.lastUpdateBlock = uint64(block.number);

    if (prevMid != 0) {
      uint64 maxChange = s.maxChangePerBlockE18;
      if (maxChange != 0) {
        uint256 blockDiff = block.number - prevBlock;

        uint256 delta = midPrice > prevMid ? uint256(midPrice - prevMid) : uint256(prevMid - midPrice);

        uint256 changeE18 = (delta * 1e18) / uint256(prevMid);

        uint256 actualSq = changeE18 * changeE18;
        uint256 allowedSq = uint256(maxChange) * uint256(maxChange) * (1 + blockDiff);

        if (actualSq > allowedSq) {
          revert PriceVelocityExceeded(actualSq, allowedSq);
        }
```
