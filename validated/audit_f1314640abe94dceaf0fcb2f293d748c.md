### Title
Missing Chain ID in L2→L1 Mint Request Messages Enables Cross-Fork Replay — (`src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The L2 `RewardSupplier` sends mint request messages to the L1 `RewardSupplier` with a payload containing only the `base_mint_amount`. Neither the L2 message payload nor the L1 message hash includes an Ethereum chain ID. If Ethereum forks, the same pending L2→L1 mint request messages would exist in the Starknet messaging contract on both Ethereum forks, and any caller can trigger `tick()` on the forked chain to consume those messages and mint tokens without a corresponding L2 reward obligation, causing protocol insolvency on the forked chain.

---

### Finding Description

In `send_mint_request_to_l1_reward_supplier`, the L2 `RewardSupplier` constructs a message payload containing only the mint amount:

```cairo
fn send_mint_request_to_l1_reward_supplier(self: @ContractState) {
    let payload: Span<felt252> = array![self.base_mint_amount.read().into()].span();
    let to_address = self.l1_reward_supplier.read();
    send_message_to_l1_syscall(:to_address, :payload).unwrap_syscall();
}
``` [1](#0-0) 

On the L1 side, the `RewardSupplier` computes the message hash as:

```solidity
keccak256(abi.encodePacked(fromAddress, uint256(uint160(toAddress)), payload.length, payload))
``` [2](#0-1) 

Neither the L2 payload nor the L1 hash includes the Ethereum `block.chainid`. The `tick()` function, callable by any address, consumes these messages and triggers minting:

```solidity
function tick() external payable {
    ...
    messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload);
    mintManager().mintRequest(token(), amountToMint);
    bridge().depositWithMessage{value: msgFee}(token(), amountToMint, mintDestination(), ...);
``` [3](#0-2) 

The Starknet messaging contract's `l2ToL1Messages` mapping stores message counts keyed by hash. If Ethereum forks, both forks inherit the same messaging contract state, including all pending L2→L1 mint request message counts. Because the hash is chain-ID-agnostic, the same messages are valid and consumable on both forks.

---

### Impact Explanation

On the forked Ethereum chain:
1. Pending mint request messages (sent from L2 before the fork) are present in the messaging contract on both forks.
2. An unprivileged attacker calls `tick()` on the forked chain's L1 `RewardSupplier`.
3. The L1 `RewardSupplier` consumes the messages, mints tokens via `MintManager`, and deposits them to the L2 `RewardSupplier` via StarkGate.
4. The L2 state on the forked chain has no corresponding reward obligations for these tokens — they are minted without any staker having earned them.
5. This inflates the token supply on the forked chain beyond what the minting curve authorizes, causing **protocol insolvency** on the forked chain.

Impact: **Protocol insolvency** (Critical tier) on the forked chain; the minted tokens are deposited into the L2 reward pool and distributed to stakers who did not earn them, constituting unauthorized yield distribution.

---

### Likelihood Explanation

Ethereum has forked before (ETH/ETC). The Starknet protocol is deployed on Ethereum mainnet. Any future contentious hard fork of Ethereum would expose this path. No privileged access is required — `tick()` is callable by any EOA with sufficient ETH for the message fee. [4](#0-3) 

---

### Recommendation

Include the Ethereum chain ID in the L2 message payload so the L1 `RewardSupplier` can reject messages intended for a different chain:

**L2 (`send_mint_request_to_l1_reward_supplier`):**
```cairo
let chain_id = starknet::get_execution_info().unbox().tx_info.unbox().chain_id;
let payload: Span<felt252> = array![self.base_mint_amount.read().into(), chain_id].span();
```

**L1 (`tick`):**
```solidity
require(messagePayload[1] == block.chainid, "WRONG_CHAIN_ID");
```

This ensures that a mint request message generated on one Ethereum chain cannot be consumed on a fork.

---

### Proof of Concept

1. L2 `RewardSupplier` calls `send_mint_request_to_l1_reward_supplier`, emitting a Starknet L2→L1 message with `payload = [base_mint_amount]`. [1](#0-0) 

2. The Starknet messaging contract on Ethereum records this message, incrementing `l2ToL1Messages[hash]`.

3. Ethereum undergoes a contentious hard fork. Both fork A (canonical) and fork B (minority) inherit the same messaging contract state, including the pending message count.

4. On fork A, `tick()` is called legitimately; the message is consumed and tokens are minted and bridged to L2.

5. On fork B, an attacker calls `tick()`. The same message hash is still present (count > 0) because the fork copied the state before consumption on fork A. The L1 `RewardSupplier` on fork B consumes the message, mints `TOKENS_PER_MINT_REQUEST` tokens, and deposits them to the L2 `mintDestination` on fork B — without any corresponding staker reward obligation on the L2 side. [5](#0-4) 

6. The L2 `RewardSupplier` on fork B receives tokens it did not request in the current epoch, and `l1_pending_requested_amount` is decremented, masking the inflation. [6](#0-5)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L247-254)
```text
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            if amount_u128 > l1_pending_requested_amount {
                self.l1_pending_requested_amount.write(Zero::zero());
            } else {
                l1_pending_requested_amount -= amount_u128;
                self.l1_pending_requested_amount.write(l1_pending_requested_amount);
            }
            true
```

**File:** src/reward_supplier/reward_supplier.cairo (L333-337)
```text
        fn send_mint_request_to_l1_reward_supplier(self: @ContractState) {
            let payload: Span<felt252> = array![self.base_mint_amount.read().into()].span();
            let to_address = self.l1_reward_supplier.read();
            send_message_to_l1_syscall(:to_address, :payload).unwrap_syscall();
        }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L51-60)
```text
    function l2ToL1MsgHash(
        uint256 fromAddress,
        address toAddress,
        uint256[] memory payload
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(fromAddress, uint256(uint160(toAddress)), payload.length, payload)
            );
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L107-132)
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
```
