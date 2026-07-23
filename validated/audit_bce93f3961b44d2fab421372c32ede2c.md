### Title
`PriceVelocityGuardExtension` Uses `block.number` for Velocity Measurement, Making the Guard Chain-Dependent and Systematically Too Permissive on Fast-Block Chains — (File: metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol)

---

### Summary

`PriceVelocityGuardExtension` measures oracle mid-price velocity using `block.number` as a time proxy. Because the protocol deploys on Ethereum (~12 s/block), Base (~2 s/block), and HyperEVM (variable), the same `maxChangePerBlockE18` value produces a guard that is proportionally more permissive on faster-block chains. A pool admin who calibrates the parameter for Ethereum semantics will unknowingly deploy a guard that is ~2.45× weaker per real-time second on Base, allowing rapid oracle price movement that the guard was intended to block.

---

### Finding Description

In `beforeSwap`, the extension computes:

```solidity
uint256 blockDiff = block.number - prevBlock;
uint256 allowedSq = uint256(maxChange) * uint256(maxChange) * (1 + blockDiff);
``` [1](#0-0) 

The allowed deviation is `maxChangePerBlockE18 × √(1 + blockDiff)`. `blockDiff` is the raw block-count difference between the current and previous swap. On Ethereum, one minute of real time produces ~5 blocks; on Base, the same minute produces ~30 blocks. For two swaps separated by one real-time minute:

| Chain | blockDiff | allowedSq factor | effective real-time allowance |
|---|---|---|---|
| Ethereum (12 s) | 5 | 6 × maxChange² | baseline |
| Base (2 s) | 30 | 31 × maxChange² | **√(31/6) ≈ 2.27× larger** |

The parameter name `maxChangePerBlockE18` and the struct field `lastUpdateBlock` both encode the assumption that one block equals one Ethereum block interval. [2](#0-1) 

There is no documentation, NatSpec, or validation warning that `maxChangePerBlockE18` must be re-calibrated per chain. The `setMaxChangePerBlock` setter accepts any `uint64` without chain-awareness. [3](#0-2) 

The protocol's own README acknowledges the velocity guard as one of the primary defenses against bad-price execution: *"manipulation risk shifts entirely to the oracle/price-provider layer; mitigated by the deviation guard, staleness checks, and the per-swap drift cap. If those guards are mis-tuned, bad-price execution is possible."* [4](#0-3) 

---

### Impact Explanation

The velocity guard is the explicit "per-swap drift cap" that the protocol relies on to prevent bad-price execution. When it is systematically too permissive on Base or HyperEVM, a rapid oracle price movement — whether from a compromised oracle update, a flash-loan-assisted price push, or any other source — can pass the guard unchallenged. A swap executed at a manipulated oracle price drains LP principal directly: the pool pays out token1 (or token0) at a price that does not reflect fair value, and the loss is borne by all LPs in the affected bins. This matches the "bad-price execution" and "direct loss of user principal" categories in the impact gate.

---

### Likelihood Explanation

- The protocol is explicitly deployed on Ethereum, Base, and HyperEVM (README line 10).
- Pool admins are semi-trusted and configure extensions themselves; there is no factory-level enforcement of chain-aware calibration.
- The parameter name `maxChangePerBlockE18` gives no indication that its meaning changes across chains.
- A pool admin who tests on Ethereum and then deploys the same configuration on Base will silently have a 2.27× weaker guard with no on-chain signal of the miscalibration.
- The trigger for the actual exploit (a swap at a manipulated price) is fully unprivileged.

---

### Recommendation

Replace `block.number` with `block.timestamp` throughout the extension, rename the parameter to `maxChangePerSecondE18`, and store `lastUpdateTimestamp` instead of `lastUpdateBlock`. The formula becomes:

```solidity
uint256 timeDiff = block.timestamp - prevTimestamp; // seconds
uint256 allowedSq = uint256(maxChange) * uint256(maxChange) * (1 + timeDiff);
```

This makes the guard chain-agnostic: the same `maxChangePerSecondE18` value produces identical real-time protection on Ethereum, Base, and HyperEVM.

---

### Proof of Concept

1. Pool admin deploys a pool on Base with `PriceVelocityGuardExtension` attached and calls `setMaxChangePerBlock` with a value calibrated for Ethereum — e.g., `maxChangePerBlockE18 = 0.01e18` (1 % per 12-second block, i.e., ~5 %/min).
2. On Base, 30 blocks pass per minute. For two swaps 60 seconds apart, `blockDiff = 30`, so `allowedSq = (0.01e18)² × 31`. The guard now permits `√31 × 1 % ≈ 5.57 %` price change per minute instead of the intended `√6 × 1 % ≈ 2.45 %`.
3. An attacker observes that the oracle price can move up to ~5.57 % per minute without triggering `PriceVelocityExceeded`.
4. The attacker arranges for the oracle mid-price to shift by 5 % within one minute (within the Base-permissive window but above the Ethereum-intended cap).
5. The attacker swaps a large amount at the shifted price; the guard does not revert.
6. LP funds are drained at the off-market price; the loss is proportional to the swap size and the price deviation. [5](#0-4) [6](#0-5)

### Citations

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L24-27)
```text
  function setMaxChangePerBlock(address pool_, uint64 newMaxPctChangePerBlockE18) external onlyPoolAdmin(pool_) {
    priceVelocityState[pool_].maxChangePerBlockE18 = newMaxPctChangePerBlockE18;
    emit MaxChangePerBlockSet(pool_, newMaxPctChangePerBlockE18);
  }
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

**File:** metric-periphery/contracts/interfaces/extensions/IPriceVelocityGuardExtension.sol (L7-11)
```text
  struct PriceVelocityState {
    uint128 lastMidPriceX64;
    uint64 lastUpdateBlock;
    uint64 maxChangePerBlockE18;
  }
```

**File:** README.md (L9-10)
```markdown
### Q: On what chains are the smart contracts going to be deployed?
Ethereum, Base, HyperEVM
```

**File:** README.md (L56-56)
```markdown
Pure oracle-anchored pricing — no internal price discovery. Price follows the oracle, not reserves; there's no DEX cross-check (the only sanity guard is the Chainlink deviation check). Trade-off: manipulation risk shifts entirely to the oracle/price-provider layer; mitigated by the deviation guard, staleness checks, and the per-swap drift cap. If those guards are mis-tuned, bad-price execution is possible.
```
