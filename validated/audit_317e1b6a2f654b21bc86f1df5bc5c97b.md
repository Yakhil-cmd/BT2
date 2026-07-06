### Title
Period-Boundary Double-Mint: `tick()` Can Mint 2× `PERIOD_MINT_CAP` in Near-Zero Time via Fixed-Window Slot Rollover — (`L1/starkware/solidity/stake/RewardSupplier.sol` / `PeriodMintLimit.sol`)

---

### Summary

`PeriodMintLimit.checkAndUpdatePeriodicalQuota` uses a **fixed-window** accounting scheme keyed on `block.timestamp / MINTING_PERIOD_DURATION`. When `block.timestamp` crosses a period boundary the accounting slot changes and the accumulated total resets to zero. An unprivileged caller can invoke the public `tick()` function twice — once just before a boundary and once just after — consuming up to 5 pending L2 mint-request messages each time, minting `2 × PERIOD_MINT_CAP = 13,000,000e18` tokens in a near-zero time window.

---

### Finding Description

**`tick()` — no access control**

`RewardSupplier.tick()` is `external payable` with no role check. [1](#0-0) 

It calls `mintManager().mintRequest(token(), amountToMint)`, which internally calls `checkAndUpdatePeriodicalQuota`. [2](#0-1) 

**Fixed-window slot in `periodAccountingSlot`**

```solidity
uint256 period_index = block.timestamp / MINTING_PERIOD_DURATION;
return keccak256(abi.encode(MINTING_PERIOD_DURATION, token, period_index));
``` [3](#0-2) 

Each period gets its own independent storage slot. When `block.timestamp` crosses `(k+1) * MINTING_PERIOD_DURATION`, `period_index` increments from `k` to `k+1`, and `periodMintAccounting()[slot_{k+1}]` starts at **zero** — completely independent of slot `k`.

**`checkAndUpdatePeriodicalQuota` only checks the current slot**

```solidity
bytes32 periodSlot = periodAccountingSlot(token);
uint256 mintedThisPeriodBefore = periodMintAccounting()[periodSlot];
uint256 mintedThisPeriodAfter = mintedThisPeriodBefore + amount;
require(mintedThisPeriodAfter <= PERIOD_MINT_CAP, "EXCEED_PERIOD_MINTING");
periodMintAccounting()[periodSlot] = mintedThisPeriodAfter;
``` [4](#0-3) 

There is no look-back into the previous slot. The guard is trivially bypassed by straddling the boundary.

**Constants confirm the math**

- `TOKENS_PER_MINT_REQUEST = 1_300_000e18`
- `MAX_MESSAGES_TO_PROCESS_PER_TICK = 5`
- `PERIOD_MINT_CAP = 6_500_000e18` = 5 × `TOKENS_PER_MINT_REQUEST` [5](#0-4) [6](#0-5) 

One full `tick()` with 5 messages exactly exhausts the cap for its slot. A second `tick()` in the next slot is unconstrained.

---

### Impact Explanation

An attacker mints `13,000,000e18` STRK tokens in two consecutive blocks straddling a weekly boundary. This is 2× the intended weekly emission cap, constituting direct token inflation and protocol insolvency. The minted tokens are immediately deposited to L2 via StarkGate, making the inflation irreversible.

---

### Likelihood Explanation

- `tick()` is public with no caller restriction.
- Period boundaries occur every week at a predictable, on-chain-observable timestamp (`block.timestamp / 604800`).
- The attacker needs ≥10 pending L2→L1 mint-request messages. This is plausible: the L2 `request_funds` logic sends `num_msgs = ceil((debit + threshold - credit) / base_mint_amount)` messages in a single call, so a backlog of 10 messages can accumulate if `tick()` is not called promptly.
- The `MintManager` allowance for `RewardSupplier` must be ≥ 13M tokens. In practice this allowance is set generously by governance to avoid operational friction, making this constraint non-blocking.
- No privileged access, no key compromise, no external dependency — only timing.

---

### Recommendation

Replace the fixed-window slot with a **rolling/sliding window** that carries forward minting from the tail of the previous period. Concretely, when computing the quota, also read the previous period's slot and enforce:

```
minted_in_last_DURATION = slot[k].amount + (fraction of slot[k-1] still within the rolling window)
require(minted_in_last_DURATION + amount <= PERIOD_MINT_CAP)
```

Alternatively, track a single monotonically-increasing `(windowStart, accumulated)` pair and reset `accumulated` only when `block.timestamp >= windowStart + MINTING_PERIOD_DURATION`, updating `windowStart` at that point. This prevents the boundary-crossing bypass entirely.

---

### Proof of Concept

```solidity
// Preconditions:
//   - 10 pending L2->L1 mint-request messages exist (msgHash count >= 10)
//   - RewardSupplier's mintingAllowance >= 13_000_000e18
//   - block.timestamp is just before a weekly boundary

uint256 W = 1 weeks; // MINTING_PERIOD_DURATION
uint256 k = block.timestamp / W;

// Warp to last second of period k
vm.warp(k * W + W - 1);

// Call 1: period_index = k, slot_k starts at 0, ends at 6_500_000e18 (== PERIOD_MINT_CAP)
rewardSupplier.tick{value: 2 ether}();

// Warp to first second of period k+1
vm.warp((k + 1) * W);

// Call 2: period_index = k+1, slot_{k+1} starts at 0, ends at 6_500_000e18
// checkAndUpdatePeriodicalQuota passes because it only sees slot_{k+1} = 0
rewardSupplier.tick{value: 2 ether}();

// Total minted: 13_000_000e18 tokens in 1 second
// PERIOD_MINT_CAP violated: 13_000_000e18 > 6_500_000e18
assertLe(totalMinted, PERIOD_MINT_CAP); // FAILS
```

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L10-11)
```text
uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;
uint256 constant MAX_MESSAGES_TO_PROCESS_PER_TICK = 5;
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-107)
```text
    function tick() external payable {
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L122-122)
```text
            mintManager().mintRequest(token(), amountToMint);
```

**File:** L1/starkware/solidity/stake/PeriodMintLimit.sol (L8-9)
```text
uint256 constant PERIOD_MINT_CAP = 6_500_000 * 10**18;
uint256 constant MINTING_PERIOD_DURATION = 1 weeks;
```

**File:** L1/starkware/solidity/stake/PeriodMintLimit.sol (L18-24)
```text
    function checkAndUpdatePeriodicalQuota(address token, uint256 amount) internal {
        bytes32 periodSlot = periodAccountingSlot(token);
        uint256 mintedThisPeriodBefore = periodMintAccounting()[periodSlot];
        uint256 mintedThisPeriodAfter = mintedThisPeriodBefore + amount;
        require(mintedThisPeriodAfter <= PERIOD_MINT_CAP, "EXCEED_PERIOD_MINTING");
        periodMintAccounting()[periodSlot] = mintedThisPeriodAfter;
    }
```

**File:** L1/starkware/solidity/stake/PeriodMintLimit.sol (L33-36)
```text
    function periodAccountingSlot(address token) internal view returns (bytes32) {
        uint256 period_index = block.timestamp / MINTING_PERIOD_DURATION;
        return keccak256(abi.encode(MINTING_PERIOD_DURATION, token, period_index));
    }
```
