### Title
Unprotected `tick()` in L1 RewardSupplier Allows Anyone to Trigger Cross-Chain Minting with Insufficient Fee, Freezing Minted Rewards in Bridge - (File: L1/starkware/solidity/stake/RewardSupplier.sol)

### Summary

`RewardSupplier.tick()` is an unprotected `external payable` function. Any caller can invoke it with `msg.value = 0` (or an arbitrarily small value). When pending L2→L1 mint-request messages exist, `tick()` irreversibly consumes them, mints STRK tokens, and then sends two L1→L2 messages — one via `bridge().depositWithMessage{value: msgFee}` and one via `messagingContract().sendMessageToL2{value: msgFee}` — where both fees are derived from `msg.value / 2`. With `msg.value = 0`, both fees are 0, causing the L1→L2 messages to be unprocessable by the Starknet sequencer. The minted tokens become stuck in the StarkGate bridge, and the L2 `RewardSupplier`'s `l1_pending_requested_amount` is never decremented (since `on_receive` is never triggered), causing future `request_funds` calls to believe sufficient credit already exists and suppressing further mint requests. Stakers and delegators are unable to claim their accrued rewards.

### Finding Description

`RewardSupplier.tick()` has no access control modifier and no minimum-fee validation:

```solidity
function tick() external payable {          // ← no onlyOwner / no fee check
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    if (amountToMint > 0) {
        for (uint256 i = 0; i < numMsgsToConsume; i++) {
            messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload); // irreversible
        }
        mintManager().mintRequest(token(), amountToMint);          // tokens minted

        uint256 msgFee = msg.value / 2;                            // 0 if msg.value == 0
        bridge().depositWithMessage{value: msgFee}(...);           // L1→L2 with 0 fee

        msgFee = msg.value - msgFee;                               // also 0
        messagingContract().sendMessageToL2{value: msgFee}(...);   // L1→L2 with 0 fee
    }
}
```

The spec itself documents this as callable by `anyAccount` (see the sequence diagram at `docs/spec.md` line 555), confirming there is no intended access restriction. The fee split `msg.value / 2` is entirely attacker-controlled.

On the L2 side, `on_receive` (the StarkGate callback that decrements `l1_pending_requested_amount`) is only triggered when the bridge's L1→L2 message is actually delivered to L2. With a 0-fee message, the Starknet sequencer has no incentive to deliver it, so `on_receive` is never called. The L2 `request_funds` logic then reads the stale (inflated) `l1_pending_requested_amount` and concludes that credit already covers the debit, suppressing all future mint requests:

```cairo
let credit = balance + l1_pending_requested_amount;  // inflated, never decremented
let debit = unclaimed_rewards;
if credit < debit + threshold {                       // condition never met → no new requests
    ...
}
```

### Impact Explanation

- Minted STRK tokens are locked in the StarkGate bridge with no automatic recovery path (the bridge, not the attacker, is the L1→L2 message sender, so the attacker cannot cancel it).
- `l1_pending_requested_amount` on L2 remains permanently inflated, blocking all future mint requests.
- Stakers and delegators cannot claim accrued rewards → **temporary (potentially permanent) freeze of unclaimed yield**.

This matches the allowed impact: **Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds**.

### Likelihood Explanation

- The entry point is fully public on Ethereum mainnet — any EOA can call `tick()` with `msg.value = 0`.
- The only precondition is that at least one L2→L1 mint-request message is pending, which is a normal operational state whenever the reward supplier needs to top up.
- No special knowledge, capital, or privileged access is required.

### Recommendation

1. **Add access control** to `tick()` so only a trusted keeper/guardian role can call it.
2. **Enforce a minimum fee** before splitting `msg.value`, e.g.:
   ```solidity
   require(msg.value >= MIN_TICK_FEE, "INSUFFICIENT_FEE");
   ```
3. Alternatively, have the contract itself hold ETH for fees and not rely on `msg.value` from an arbitrary caller.

### Proof of Concept

1. L2 `RewardSupplier` calls `send_mint_request_to_l1_reward_supplier()`, placing one or more L2→L1 messages.
2. Attacker calls `RewardSupplier.tick{value: 0}()` on L1.
3. `requiredMinting()` returns `amountToMint = 1_300_000e18`, `numMsgsToConsume = 1`.
4. The L2→L1 message is consumed (irreversible).
5. `mintManager().mintRequest(token(), 1_300_000e18)` mints tokens to `RewardSupplier`.
6. `bridge().depositWithMessage{value: 0}(...)` — tokens transferred to bridge, L1→L2 message recorded with fee = 0.
7. `messagingContract().sendMessageToL2{value: 0}(...)` — totalSupply update message recorded with fee = 0.
8. Starknet sequencer does not process either 0-fee message.
9. L2 `on_receive` is never called; `l1_pending_requested_amount` stays at `1_300_000e18`.
10. Next epoch: `request_funds` computes `credit = balance + 1_300_000e18 >= debit + threshold` → no new mint request sent.
11. L2 reward supplier has no tokens to pay out; `claim_rewards` calls from the staking contract fail or drain the existing balance to zero, freezing staker/delegator reward withdrawals.

---

**Root cause references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-107)
```text
    function tick() external payable {
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L124-131)
```text
            // Deposit the minted amount onto the bridge to the credit of `mintDestination`.
            uint256 msgFee = msg.value / 2;
            bridge().depositWithMessage{value: msgFee}(
                token(),
                amountToMint,
                mintDestination(),
                new uint256[](0)
            );
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L134-141)
```text
            // Send a totalSupply update to L2MintCurve.
            msgFee = msg.value - msgFee;
            messagePayload[0] = IERC20(token()).totalSupply();
            messagingContract().sendMessageToL2{value: msgFee}(
                mintingCurve(),
                UPDATE_TOTAL_SUPPLY_SELECTOR,
                messagePayload
            );
```

**File:** src/reward_supplier/reward_supplier.cairo (L247-253)
```text
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            if amount_u128 > l1_pending_requested_amount {
                self.l1_pending_requested_amount.write(Zero::zero());
            } else {
                l1_pending_requested_amount -= amount_u128;
                self.l1_pending_requested_amount.write(l1_pending_requested_amount);
            }
```

**File:** src/reward_supplier/reward_supplier.cairo (L311-318)
```text
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            let credit = balance + l1_pending_requested_amount;
            let debit = unclaimed_rewards;

            // If there isn't enough credit to cover the debit + threshold, request funds.
            let base_mint_amount = self.base_mint_amount.read();
            let threshold = compute_threshold(base_mint_amount);
            if credit < debit + threshold {
```

**File:** docs/spec.md (L551-560)
```markdown
  participant RewardSupplier
  participant MintingManager
  participant STRK ERC20
  participant StarkGate bridge
  anyAccount ->>+ RewardSupplier: tick(tokensPerMintAmount, maxMessagesToProcess)
  RewardSupplier ->>+ MintingManager: mintRequest(totalAmountToMint)
  MintingManager ->>- STRK ERC20: mint
  RewardSupplier ->>+ StarkGate bridge: depositWithMessage
  deactivate RewardSupplier
```
```
