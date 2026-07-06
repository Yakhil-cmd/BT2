### Title
No `msg.value` Minimum Check in `tick()` Causes Minted Reward Tokens to Be Stuck — (`File: L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

The `RewardSupplier.tick()` function is a public payable function that mints STRK reward tokens and sends them to L2 via two L1→L2 messages. It accepts any `msg.value`, including zero, with no minimum fee validation. When called with insufficient ETH, the L1→L2 messages are registered with zero or near-zero fees, causing the sequencer to not process the L2 handlers. The minted tokens become stuck in the StarkGate bridge, and stakers/delegators are permanently denied those reward tokens until a cancellation window expires.

---

### Finding Description

`tick()` is declared `external payable` with no access control and no `msg.value` floor check: [1](#0-0) 

When `amountToMint > 0`, the function performs three irreversible state-changing operations in sequence:

1. Consumes the pending L2→L1 mint-request messages (line 117–119) — these are gone after this step.
2. Mints `amountToMint` STRK tokens on L1 (line 122).
3. Splits `msg.value` arbitrarily as `msg.value / 2` for `depositWithMessage` and the remainder for `sendMessageToL2`: [2](#0-1) 

If `msg.value == 0`:
- `msgFee = 0 / 2 = 0` → `bridge().depositWithMessage{value: 0}(...)` is called. The StarkGate bridge registers an L1→L2 message with a 0-wei fee. The Starknet sequencer will not process the L2 handler, so the minted tokens sit locked in the bridge.
- `msgFee = 0 - 0 = 0` → `messagingContract().sendMessageToL2{value: 0}(...)` is called. The `update_total_supply` message to the L2 MintingCurve is also registered with 0 fee and will not be processed.

There is no `receive()`, `fallback()`, or ETH-withdrawal function anywhere in the contract: [3](#0-2) 

A secondary issue: when `amountToMint == 0` (no pending mint requests), the function body is skipped entirely, but any ETH sent with the call is permanently locked in the contract with no recovery path.

---

### Impact Explanation

When `tick()` is called with `msg.value = 0` and pending mint requests exist:

- STRK reward tokens are minted on L1 and deposited into the StarkGate bridge, but the corresponding L2 credit message is never processed by the sequencer.
- The L2 `RewardSupplier` never receives the tokens, so it cannot distribute rewards to stakers and delegators.
- The tokens remain frozen in the bridge. Recovery requires initiating a message cancellation, which has a mandatory delay (5 days on mainnet), constituting a **temporary freezing of funds** and **theft of unclaimed yield** for all stakers and delegators during that period.
- The `update_total_supply` message to the L2 MintingCurve also fails, causing the minting curve to operate on a stale total supply, which can distort future reward calculations.

This matches the allowed impacts: **Temporary freezing of funds** and **Theft of unclaimed yield**.

---

### Likelihood Explanation

`tick()` has no access control — it is callable by any EOA or contract. A griefing attacker (or simply a misconfigured keeper bot) can call it with `msg.value = 0` at any time when pending mint requests exist. The cost to the attacker is only the gas for the call. The L2 mint-request messages are consumed and cannot be re-used, so the minted tokens are permanently stranded until the bridge cancellation window expires.

---

### Recommendation

Add a minimum fee guard at the top of `tick()` before any state changes occur:

```solidity
function tick() external payable {
    require(msg.value >= MIN_TICK_FEE, "INSUFFICIENT_FEE");
    ...
}
```

Where `MIN_TICK_FEE` accounts for the 20,000-wei storage registration cost per L1→L2 message plus the L2 execution fee for both `depositWithMessage` and `sendMessageToL2`. Alternatively, expose a `estimateTickFee()` view function so callers can query the required amount before calling. Also consider reverting when `amountToMint == 0` to prevent ETH from being permanently locked.

---

### Proof of Concept

```solidity
// Attacker calls tick() with zero ETH when pending mint requests exist.
// The L2->L1 mint request messages are consumed (irreversible).
// Tokens are minted and deposited to the bridge with 0-wei fee.
// The L2 handler is never executed; tokens are stuck.
rewardSupplier.tick{value: 0}();
```

Concretely, with `msg.value = 0`:
- Line 125: `msgFee = 0 / 2 = 0`
- Line 126: `bridge().depositWithMessage{value: 0}(token, amountToMint, mintDestination, [])` — L1→L2 message registered with fee=0
- Line 135: `msgFee = 0 - 0 = 0`
- Line 137: `messagingContract().sendMessageToL2{value: 0}(mintingCurve, UPDATE_TOTAL_SUPPLY_SELECTOR, [totalSupply])` — L1→L2 message registered with fee=0

Both messages are registered in the Starknet Core contract storage (costing the caller only gas), but the sequencer will not pick them up, leaving `amountToMint` STRK tokens permanently frozen in the bridge. [1](#0-0)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-144)
```text
    function tick() external payable {
        // Check if minting is required, and how much.
        (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

        if (amountToMint > 0) {
            // Prepare the L2->L1 mintRequest message for consumption.
            uint256[] memory messagePayload = new uint256[](1);
            messagePayload[0] = TOKENS_PER_MINT_REQUEST;

            // Consume the mintRequest messages.
            for (uint256 i = 0; i < numMsgsToConsume; i++) {
                messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload);
            }

            // Reuest minting of the requested amount from the mint manager.
            mintManager().mintRequest(token(), amountToMint);

            // Deposit the minted amount onto the bridge to the credit of `mintDestination`.
            uint256 msgFee = msg.value / 2;
            bridge().depositWithMessage{value: msgFee}(
                token(),
                amountToMint,
                mintDestination(),
                new uint256[](0)
            );
            emit ConsumedL2MintRequests(numMsgsToConsume, amountToMint);

            // Send a totalSupply update to L2MintCurve.
            msgFee = msg.value - msgFee;
            messagePayload[0] = IERC20(token()).totalSupply();
            messagingContract().sendMessageToL2{value: msgFee}(
                mintingCurve(),
                UPDATE_TOTAL_SUPPLY_SELECTOR,
                messagePayload
            );
        }
    }
}
```
