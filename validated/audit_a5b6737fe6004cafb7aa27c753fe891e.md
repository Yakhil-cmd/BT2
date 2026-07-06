### Title
Insufficient L1→L2 Message Fee in `tick()` Allows Minted Reward Tokens to Be Frozen in Bridge - (File: L1/starkware/solidity/stake/RewardSupplier.sol)

---

### Summary

The `tick()` function in `RewardSupplier.sol` sends two L1→L2 messages — one via the StarkGate bridge (`depositWithMessage`) and one via the Starknet messaging contract (`sendMessageToL2`) — splitting `msg.value` as `msg.value / 2` with no minimum fee validation. Because `tick()` is a public, permissionless, payable function, any caller can invoke it with 0 or near-zero ETH. If the fee attached to either L1→L2 message is insufficient, the Starknet sequencer will not process the message, leaving minted reward tokens permanently stuck in the bridge and the total-supply update undelivered to the MintingCurve contract on L2.

---

### Finding Description

`tick()` is declared `external payable` with no access control and no floor check on `msg.value`:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();

    if (amountToMint > 0) {
        for (uint256 i = 0; i < numMsgsToConsume; i++) {
            messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload); // irreversible
        }
        mintManager().mintRequest(token(), amountToMint);                                  // irreversible

        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(                                        // L1→L2 #1
            token(), amountToMint, mintDestination(), new uint256[](0)
        );

        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(                                // L1→L2 #2
            mintingCurve(), UPDATE_TOTAL_SUPPLY_SELECTOR, messagePayload
        );
    }
}
```

The execution sequence has a critical ordering problem:

1. **Irreversible state changes first**: L2→L1 mint-request messages are consumed and tokens are minted on L1 before any fee is validated.
2. **Arbitrary 50/50 fee split**: `msg.value / 2` is used for each message with no relationship to the actual fee required by the Starknet sequencer.
3. **No minimum fee guard**: If `msg.value == 0`, both `depositWithMessage{value: 0}` and `sendMessageToL2{value: 0}` are called. In Starknet's messaging model, L1→L2 messages are registered with fee `msg.value + 1`; a fee of 1 (the minimum storable value) is far below what the sequencer requires to include the message in a block.

Because the L2→L1 message consumption and the L1 mint are already committed before the L1→L2 sends, a revert in the bridge call does not help — the consumed messages and minted tokens cannot be rolled back if the bridge itself accepts a 0-fee call without reverting (which the `IBridge` interface does not prohibit). [1](#0-0) [2](#0-1) 

---

### Impact Explanation

- **Temporary (potentially permanent) freezing of funds**: Minted STRK reward tokens are deposited into the StarkGate bridge on L1 but the corresponding L1→L2 message carries an insufficient fee. The Starknet sequencer will not process the message, so the tokens never arrive at the L2 `RewardSupplier`. Starknet's messaging model does not allow a fee top-up on an already-registered message, making the freeze potentially permanent until a protocol-level intervention.
- **Disrupted reward accounting**: The `sendMessageToL2` call for `UPDATE_TOTAL_SUPPLY_SELECTOR` also carries an insufficient fee, so the MintingCurve contract on L2 never receives the updated total supply, corrupting future reward calculations.

This matches the allowed impact: **Temporary freezing of funds** (and potentially permanent freezing of unclaimed yield). [3](#0-2) 

---

### Likelihood Explanation

- `tick()` is a fully public, permissionless function — any EOA or contract can call it.
- The spec diagram explicitly labels the caller as `anyAccount`.
- Calling with `msg.value = 0` costs only the L1 gas for the transaction itself, making the griefing attack essentially free.
- The attacker does not need any tokens, roles, or special permissions. [4](#0-3) 

---

### Recommendation

1. **Add a minimum fee guard** at the top of `tick()`:
   ```solidity
   require(msg.value >= MIN_L1_TO_L2_FEE * 2, "INSUFFICIENT_FEE");
   ```
   where `MIN_L1_TO_L2_FEE` is derived from `messagingContract().getMaxL1MsgFee()` or a governance-configurable constant.

2. **Allow the caller to specify the fee split** rather than hardcoding a 50/50 division, since `depositWithMessage` and `sendMessageToL2` may have different fee requirements.

3. **Validate fee sufficiency before consuming L2→L1 messages**, so that if the fee is insufficient the entire call reverts cleanly without consuming irreversible state. [5](#0-4) 

---

### Proof of Concept

```solidity
// Attacker calls tick() with 0 ETH.
// 1. requiredMinting() returns (amountToMint > 0, numMsgsToConsume > 0)
//    because the L2 RewardSupplier has sent mint-request messages.
// 2. consumeMessageFromL2() is called numMsgsToConsume times — irreversible.
// 3. mintManager().mintRequest() mints amountToMint STRK on L1 — irreversible.
// 4. bridge().depositWithMessage{value: 0}(...) — L1→L2 message registered
//    with fee = 1 (minimum storable), far below sequencer threshold.
// 5. messagingContract().sendMessageToL2{value: 0}(...) — same issue.
// Result: STRK tokens are locked in the StarkGate bridge on L1 and will
//         never be delivered to the L2 RewardSupplier.

rewardSupplier.tick{value: 0}();

// Verify: tokens are in the bridge but the L2 RewardSupplier balance
// has not increased, and l1_pending_requested_amount on L2 is never
// decremented (on_receive is never called).
``` [6](#0-5) [7](#0-6)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-143)
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
```

**File:** L1/starkware/solidity/stake/RewardSupplierExternalInterfaces.sol (L7-14)
```text
interface IBridge {
    function depositWithMessage(
        address token,
        uint256 amount,
        uint256 l2Recipient,
        uint256[] calldata message
    ) external payable;
}
```

**File:** L1/starkware/starknet/solidity/IStarknetMessaging.sol (L9-10)
```text
    */
    function getMaxL1MsgFee() external pure returns (uint256);
```

**File:** src/reward_supplier/reward_supplier.cairo (L222-255)
```text
        fn on_receive(
            ref self: ContractState,
            l2_token: ContractAddress,
            amount: u256,
            depositor: EthAddress,
            message: Span<felt252>,
        ) -> bool {
            // Note that the deposit can be done by anyone (not just the L1 reward supplier), so
            // depositor is not checked.

            // These messages accepted only from the token bridge.
            assert!(
                get_caller_address() == self.starkgate_address.read(),
                "{}",
                Error::ON_RECEIVE_NOT_FROM_STARKGATE,
            );
            // The bridge may serve multiple tokens, only the correct token may be received.
            assert!(
                l2_token == self.token_dispatcher.contract_address.read(),
                "{}",
                Error::UNEXPECTED_TOKEN,
            );
            let amount_u128: Amount = amount
                .try_into()
                .expect_with_err(GenericError::AMOUNT_TOO_HIGH);
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            if amount_u128 > l1_pending_requested_amount {
                self.l1_pending_requested_amount.write(Zero::zero());
            } else {
                l1_pending_requested_amount -= amount_u128;
                self.l1_pending_requested_amount.write(l1_pending_requested_amount);
            }
            true
        }
```
