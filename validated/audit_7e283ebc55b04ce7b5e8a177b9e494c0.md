Looking at the actual production code to verify this claim.

### Title
Period Boundary Race in `PeriodMintLimit.checkAndUpdatePeriodicalQuota` Allows 2× Weekly Cap Mint in ~13 Seconds — (`L1/starkware/solidity/stake/PeriodMintLimit.sol`)

---

### Summary

`PeriodMintLimit.checkAndUpdatePeriodicalQuota` keys its accounting on a discrete `period_index = block.timestamp / MINTING_PERIOD_DURATION`. When two `tick()` calls straddle a period boundary, each call reads a fresh, independent storage slot starting at zero. An unprivileged caller can therefore mint up to `2 × PERIOD_MINT_CAP = 13,000,000` tokens in a ~13-second window, violating the invariant that no more than `PERIOD_MINT_CAP` tokens may be minted per week.

---

### Finding Description

`periodAccountingSlot` computes the storage key as:

```solidity
uint256 period_index = block.timestamp / MINTING_PERIOD_DURATION;
return keccak256(abi.encode(MINTING_PERIOD_DURATION, token, period_index));
``` [1](#0-0) 

When `block.timestamp` crosses a week boundary, `period_index` increments by 1, producing a completely new `bytes32` key whose accumulated value in `periodMintAccounting()` is 0. The cap check:

```solidity
require(mintedThisPeriodAfter <= PERIOD_MINT_CAP, "EXCEED_PERIOD_MINTING");
``` [2](#0-1) 

passes independently for each period slot. There is no rolling-window or cross-period accumulation.

`tick()` in `RewardSupplier` is entirely unguarded — no role check, no caller restriction:

```solidity
function tick() external payable {
``` [3](#0-2) 

Per call, `requiredMinting()` caps consumption at `MAX_MESSAGES_TO_PROCESS_PER_TICK = 5` messages × `TOKENS_PER_MINT_REQUEST = 1,300,000` = exactly `PERIOD_MINT_CAP = 6,500,000` tokens: [4](#0-3) [5](#0-4) 

**Attack sequence:**

1. Attacker monitors the L2→L1 message queue. If ≥10 messages are pending (which accumulates naturally when `tick()` is not called promptly), the precondition is met.
2. Attacker waits until `block.timestamp % MINTING_PERIOD_DURATION >= MINTING_PERIOD_DURATION - 12` (last ~12 seconds of period N).
3. Attacker calls `tick()` at timestamp T (period N): consumes 5 messages, mints 6,500,000 tokens. `checkAndUpdatePeriodicalQuota` writes 6,500,000 to slot for period N — passes.
4. Attacker waits ~13 seconds for the next block (timestamp T+13, period N+1).
5. Attacker calls `tick()` again: consumes 5 more messages, mints another 6,500,000 tokens. `checkAndUpdatePeriodicalQuota` reads slot for period N+1 (value = 0), writes 6,500,000 — passes again.

Total minted: **13,000,000 tokens in ~13 seconds**.

The `mintingAllowance` check in `MintManager.mintRequest` is a separate, manually-managed value:

```solidity
require(mintingAllowance(token)[requester] >= amount, "INSUFFICIENT_MINTING_ALLOWANCE");
...
mintingAllowance(token)[requester] -= amount;
``` [6](#0-5) 

It is not reset per period and is expected to be set to a large value to cover normal multi-week operation, so it does not prevent the double-mint.

---

### Impact Explanation

`PERIOD_MINT_CAP` is the sole on-chain rate-limit on token inflation. Minting 13,000,000 tokens in 13 seconds — double the intended weekly maximum — causes uncontrolled hyperinflation of the staking reward token. All stakers and token holders suffer immediate dilution. This constitutes **protocol insolvency** under the Critical impact category.

---

### Likelihood Explanation

- `tick()` is callable by any EOA or contract with no privilege requirement.
- Pending messages accumulate naturally whenever `tick()` is not called for an extended period (e.g., over a weekend), making ≥10 messages a realistic steady-state.
- The attacker only needs to time two transactions around a weekly boundary — a deterministic, predictable event.
- No special capital, flash loans, or governance access is required.

---

### Recommendation

Replace the discrete-period slot with a **rolling window** accumulator, or enforce a single global cap that is not keyed by period index. One concrete fix: track `(lastMintTimestamp, cumulativeMinted)` and reset `cumulativeMinted` only after a full `MINTING_PERIOD_DURATION` has elapsed since `lastMintTimestamp`, rather than at a fixed calendar boundary. Alternatively, cap the total minted across any sliding 7-day window using a circular buffer.

---

### Proof of Concept

```solidity
// Pseudocode — warp-based Foundry test
function test_periodBoundaryDoubleMint() public {
    // Arrange: queue 10 L2->L1 mint-request messages
    _queueL2Messages(10);
    // Set minting allowance high enough
    vm.prank(tokenAdmin);
    mintManager.setMintingAllowance(token, address(rewardSupplier), 2 * PERIOD_MINT_CAP);

    // Warp to last second of period N
    uint256 periodEnd = (block.timestamp / 1 weeks + 1) * 1 weeks;
    vm.warp(periodEnd - 1);

    // First tick — period N, mints PERIOD_MINT_CAP
    rewardSupplier.tick{value: 2 ether}();
    uint256 mintedAfterFirst = token.totalSupply() - initialSupply;
    assertEq(mintedAfterFirst, PERIOD_MINT_CAP);

    // Warp 13 seconds — now period N+1
    vm.warp(periodEnd + 12);

    // Second tick — period N+1, mints another PERIOD_MINT_CAP
    rewardSupplier.tick{value: 2 ether}();
    uint256 mintedTotal = token.totalSupply() - initialSupply;

    // Invariant violated: 13_000_000 tokens minted in ~13 seconds
    assertEq(mintedTotal, 2 * PERIOD_MINT_CAP); // 13_000_000 * 10**18
}
```

### Citations

**File:** L1/starkware/solidity/stake/PeriodMintLimit.sol (L8-9)
```text
uint256 constant PERIOD_MINT_CAP = 6_500_000 * 10**18;
uint256 constant MINTING_PERIOD_DURATION = 1 weeks;
```

**File:** L1/starkware/solidity/stake/PeriodMintLimit.sol (L22-22)
```text
        require(mintedThisPeriodAfter <= PERIOD_MINT_CAP, "EXCEED_PERIOD_MINTING");
```

**File:** L1/starkware/solidity/stake/PeriodMintLimit.sol (L33-36)
```text
    function periodAccountingSlot(address token) internal view returns (bytes32) {
        uint256 period_index = block.timestamp / MINTING_PERIOD_DURATION;
        return keccak256(abi.encode(MINTING_PERIOD_DURATION, token, period_index));
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L10-11)
```text
uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;
uint256 constant MAX_MESSAGES_TO_PROCESS_PER_TICK = 5;
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-107)
```text
    function tick() external payable {
```

**File:** L1/starkware/solidity/stake/MintManager.sol (L56-60)
```text
        require(mintingAllowance(token)[requester] >= amount, "INSUFFICIENT_MINTING_ALLOWANCE");

        // Update allowance.
        checkAndUpdatePeriodicalQuota(token, amount);
        mintingAllowance(token)[requester] -= amount;
```
