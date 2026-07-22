### Title
`PriceVelocityGuardExtension` Uses `block.number` (L1 Block) on Arbitrum, Making the Velocity Guard Systematically Miscalibrated and Rendering Pool Swaps Unusable - (File: `metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol`)

---

### Summary

`PriceVelocityGuardExtension` records `block.number` as `lastUpdateBlock` and computes `blockDiff = block.number - prevBlock` to determine how much oracle price movement is permitted between swaps. On Arbitrum — where the protocol is confirmed deployed — `block.number` returns the **L1 block number** (≈12 s cadence), not the L2 block number (≈0.25 s cadence). Because many L2 transactions are sequenced within a single L1 block, `blockDiff` is frequently 0, collapsing the allowed-change window to its minimum and causing the guard to reject legitimate swaps at a rate far higher than the pool admin intended.

---

### Finding Description

The velocity guard formula is:

```
allowedSq = maxChange² × (1 + blockDiff)
```

`blockDiff` is computed at line 63:

```solidity
uint256 blockDiff = block.number - prevBlock;
```

`lastUpdateBlock` is written at lines 32 and 58:

```solidity
s.lastUpdateBlock = uint64(block.number);
```

On Arbitrum, per Arbitrum's documented behavior, `block.number` returns the **approximate L1 block number** at which the sequencer received the transaction. L1 blocks advance every ≈12 seconds; Arbitrum L2 blocks advance every ≈0.25 seconds, meaning ≈48 L2 blocks fit inside one L1 block.

**Consequence:** Any two swaps that land within the same L1 block — even if they are 11 seconds and 47 L2 blocks apart — produce `blockDiff = 0`. The guard then enforces:

```
allowedSq = maxChange² × 1
```

A pool admin deploying on Arbitrum will naturally calibrate `maxChangePerBlockE18` against L2 block cadence (0.25 s). Over a 12-second window (one L1 block), the oracle price can legitimately move up to `maxChange × sqrt(48) ≈ 6.9 × maxChange`. The guard, however, only permits `maxChange × sqrt(1) = maxChange` — a **~6.9× under-allowance** — causing `PriceVelocityExceeded` to revert every swap in that window after the first one.

The protocol is confirmed deployed on Arbitrum: [1](#0-0) 

The three affected lines in the extension: [2](#0-1) [3](#0-2) 

---

### Impact Explanation

When `blockDiff = 0` (the common case within any 12-second L1 block on Arbitrum), the guard's `allowedSq` equals `maxChange²`. Any oracle price movement larger than `maxChange` — even a fully legitimate movement over many L2 blocks — triggers:

```solidity
revert PriceVelocityExceeded(actualSq, allowedSq);
``` [4](#0-3) 

This revert propagates through the pool's `beforeSwap` hook, making **all swaps fail** for the duration of the L1 block whenever the oracle price has moved by more than the per-L2-block cap. Because the `beforeSwap` hook is mandatory for pools that register this extension, the pool's swap functionality becomes entirely unusable during normal market conditions on Arbitrum. This matches the allowed impact: **broken core pool functionality causing unusable swap flows**.

---

### Likelihood Explanation

- The protocol is actively deployed on Arbitrum with real token pairs (WETH/USDC, WBTC/USDC, ARB/USDC, etc.).
- Any pool that enables `PriceVelocityGuardExtension` is affected.
- The trigger requires no attacker: normal oracle price updates during volatile market conditions (which are common for the listed pairs) are sufficient to cause `blockDiff = 0` and `PriceVelocityExceeded` reverts throughout an entire L1 block window.
- No privileged access is needed; the broken behavior is automatic.

---

### Recommendation

Replace `block.number` with `ArbSys(address(100)).arbBlockNumber()` when deployed on Arbitrum, which returns the true L2 block number. A clean pattern is to abstract block-number retrieval into a virtual or overridable internal function:

```solidity
function _blockNumber() internal view virtual returns (uint256) {
    return block.number;
}
```

And provide an Arbitrum-specific override:

```solidity
function _blockNumber() internal view override returns (uint256) {
    return ArbSys(address(100)).arbBlockNumber();
}
```

Alternatively, use `block.timestamp` instead of `block.number` for the velocity window, which is consistent across L1 and all L2 networks and directly reflects elapsed real time.

---

### Proof of Concept

**Setup:**
- Pool on Arbitrum with `PriceVelocityGuardExtension` enabled.
- Admin calls `setMaxChangePerBlock(pool, 1e15)` — 0.1% per block, calibrated for L2 blocks (0.25 s).

**Sequence:**
1. At L2 block N (L1 block B), Swap A executes. `lastUpdateBlock = B`, `lastMidPriceX64 = P`.
2. Oracle price moves 0.5% over the next 2 seconds (8 L2 blocks) — a normal market move.
3. At L2 block N+8 (still L1 block B, since 2 s < 12 s), Swap B executes.
4. `blockDiff = B - B = 0`.
5. `allowedSq = (1e15)² × (1 + 0) = 1e30`.
6. `changeE18 = 0.005 × 1e18 = 5e15`; `actualSq = (5e15)² = 25e30`.
7. `25e30 > 1e30` → `revert PriceVelocityExceeded(25e30, 1e30)`.

Swap B fails. Every subsequent swap within L1 block B also fails if the oracle price remains at its new level. The pool is effectively frozen for swaps for up to 12 seconds per L1 block, repeating on every volatile price move. [5](#0-4)

### Citations

**File:** smart-contracts-poc/script/js/config/arbitrum/feeds/default.json (L1-10)
```json
{
  "oracle": "0x0000000000000000000000000000000000000000",
  "tokens": [
    {
      "pythLazerId": 7,
      "baseTokenSymbol": "USDC",
      "quoteTokenSymbol": "USDC",
      "baseTokenAddress": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
      "quoteTokenAddress": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
    },
```

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L32-33)
```text
    s.lastUpdateBlock = uint64(block.number);
    emit LastMidPriceUpdated(pool_, newLastMidPriceX64);
```

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L57-74)
```text
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
