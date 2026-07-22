### Title
`PriceVelocityGuardExtension` uses `block.number` for velocity scaling, rendering the guard ineffective on fast-block L2 target chains — (File: `metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol`)

---

### Summary

`PriceVelocityGuardExtension.beforeSwap` measures elapsed time between swaps using `block.number` and scales the allowed price movement as `maxChange * sqrt(1 + blockDiff)`. The protocol explicitly targets Base and HyperEVM — chains where L2 blocks are produced every ~2 seconds or faster. A pool admin who calibrates `maxChangePerBlockE18` against Ethereum mainnet's ~12-second block time will find the guard allows proportionally larger price swings on fast-block chains, silently defeating the protection it was deployed to provide.

---

### Finding Description

In `beforeSwap`, the extension records and compares `block.number`: [1](#0-0) 

The allowed-change formula is: [2](#0-1) 

`blockDiff` is the raw difference in `block.number` values. On Ethereum mainnet a 10-minute gap produces ~50 blocks; on Base (OP Stack, ~2 s/block) the same gap produces ~300 blocks. Because the allowed deviation scales with `sqrt(1 + blockDiff)`, the guard is `sqrt(301/51) ≈ 2.4×` more permissive on Base than the admin intended. On HyperEVM, which targets sub-second block times, the multiplier grows even larger.

The same `block.number` is also written in `setLastMidPrice`: [3](#0-2) 

Both write paths share the same `lastUpdateBlock` field, so the miscalibration affects every subsequent `beforeSwap` check.

The protocol's deployment targets are stated as Ethereum Mainnet, Base, and HyperEVM: [4](#0-3) 

---

### Impact Explanation

When `blockDiff` is inflated by fast L2 block production, the velocity cap is silently widened far beyond the admin's intent. A price provider that moves the oracle price rapidly — or an oracle that is momentarily manipulated — can push a bid/ask quote through `beforeSwap` that the guard was specifically deployed to reject. LPs are exposed to trades executed at prices that deviate from the intended velocity envelope, resulting in direct loss of LP assets. The guard provides false security: it is present in the extension slot, passes `ValidateExtensionsConfig`, and emits no warning, yet it does not enforce the configured cap on the target chain.

---

### Likelihood Explanation

Base is an explicitly supported deployment target. Any pool on Base that installs `PriceVelocityGuardExtension` and sets `maxChangePerBlockE18` based on Ethereum block cadence is immediately affected. No privileged attacker is required; the miscalibration is structural and activates on every swap after a multi-block gap.

---

### Recommendation

Replace `block.number` with `block.timestamp` throughout `PriceVelocityGuardExtension`. Store `lastUpdateTimestamp` (seconds) instead of `lastUpdateBlock`, and express `maxChangePerBlockE18` as `maxChangePerSecondE18`. The velocity formula becomes:

```solidity
uint256 timeDiff = block.timestamp - prevTimestamp;
uint256 allowedSq = uint256(maxChange) * uint256(maxChange) * (1 + timeDiff);
```

`block.timestamp` is consistent and monotonically increasing on all EVM-compatible L2s, including Base and HyperEVM, making the guard chain-agnostic.

---

### Proof of Concept

1. Deploy a pool on Base with `PriceVelocityGuardExtension` installed.
2. Pool admin calls `setMaxChangePerBlock(pool, 0.01e18)` — intending "1 % per Ethereum block (~12 s)".
3. No swap occurs for 10 minutes. On Base this produces `blockDiff ≈ 300`.
4. A price provider moves the mid-price by 17 %:
   - `changeE18 = 0.17e18`
   - `actualSq = (0.17e18)^2 = 2.89e34`
   - `allowedSq = (0.01e18)^2 * 301 = 3.01e34`
   - `actualSq < allowedSq` → guard **passes**, swap executes.
5. On Ethereum mainnet the same 10-minute gap gives `blockDiff ≈ 50`:
   - `allowedSq = (0.01e18)^2 * 51 = 5.1e33`
   - `actualSq > allowedSq` → guard **reverts**, swap blocked.
6. The 17 % price move that the admin intended to block on every chain is silently permitted on Base, exposing LPs to the full adverse-price trade.

### Citations

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L29-34)
```text
  function setLastMidPrice(address pool_, uint128 newLastMidPriceX64) external onlyPoolAdmin(pool_) {
    PriceVelocityState storage s = priceVelocityState[pool_];
    s.lastMidPriceX64 = newLastMidPriceX64;
    s.lastUpdateBlock = uint64(block.number);
    emit LastMidPriceUpdated(pool_, newLastMidPriceX64);
  }
```

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L55-63)
```text
    uint64 prevBlock = s.lastUpdateBlock;

    s.lastMidPriceX64 = midPrice;
    s.lastUpdateBlock = uint64(block.number);

    if (prevMid != 0) {
      uint64 maxChange = s.maxChangePerBlockE18;
      if (maxChange != 0) {
        uint256 blockDiff = block.number - prevBlock;
```

**File:** metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol (L69-73)
```text
        uint256 actualSq = changeE18 * changeE18;
        uint256 allowedSq = uint256(maxChange) * uint256(maxChange) * (1 + blockDiff);

        if (actualSq > allowedSq) {
          revert PriceVelocityExceeded(actualSq, allowedSq);
```

**File:** README.md (L1-10)
```markdown
# Metric contest details

- Join [Sherlock Discord](https://discord.gg/MABEWyASkp)
- Submit findings using the **Issues** page in your private contest repo (label issues as **Medium** or **High**)
- [Read for more details](https://docs.sherlock.xyz/audits/watsons)

# Q&A

### Q: On what chains are the smart contracts going to be deployed?
Ethereum, Base, HyperEVM
```
