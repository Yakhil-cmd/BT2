### Title
No Way to Cancel L1→L2 `update_total_supply` Messages in `RewardSupplier` — (File: `L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

The L1 `RewardSupplier.tick()` function sends an L1→L2 message to the L2 `MintingCurve` contract via `messagingContract().sendMessageToL2{value: msgFee}(...)`. The `RewardSupplier` contract exposes no mechanism to call `startL1ToL2MessageCancellation` or `cancelL1ToL2Message` on the Starknet messaging contract, even though the `IStarknetMessaging` interface it already holds a reference to explicitly exposes both cancellation functions. If the pending L1→L2 message cannot be consumed on L2, the ETH fee paid by the `tick()` caller is permanently lost with no recovery path.

---

### Finding Description

`RewardSupplier.tick()` is an unrestricted `external payable` function. When L2→L1 mint-request messages are pending, it:

1. Consumes those L2→L1 messages.
2. Mints STRK and bridges it to L2 via StarkGate.
3. Sends a new **L1→L2** message to the L2 `MintingCurve` contract to update `total_supply`:

```solidity
// L1/starkware/solidity/stake/RewardSupplier.sol lines 134-141
// Send a totalSupply update to L2MintCurve.
msgFee = msg.value - msgFee;
messagePayload[0] = IERC20(token()).totalSupply();
messagingContract().sendMessageToL2{value: msgFee}(
    mintingCurve(),
    UPDATE_TOTAL_SUPPLY_SELECTOR,
    messagePayload
);
``` [1](#0-0) 

The fee forwarded to `sendMessageToL2` is `msg.value - msg.value/2` (the second half of `msg.value`). [2](#0-1) 

The `IStarknetMessaging` interface that `messagingContract()` returns **already** declares both cancellation entry points:

```solidity
// L1/starkware/starknet/solidity/IStarknetMessaging.sol lines 71-91
function startL1ToL2MessageCancellation(...) external returns (bytes32);
function cancelL1ToL2Message(...) external returns (bytes32);
``` [3](#0-2) 

However, `RewardSupplier` never wraps or exposes these calls. The entire contract contains only `tick()`, `requiredMinting()`, and initialization helpers — no cancellation surface at all. [4](#0-3) 

On the L2 side, the target `#[l1_handler]` is `update_total_supply` in `MintingCurve`:

```cairo
// src/minting_curve/minting_curve.cairo lines 118-135
#[l1_handler]
fn update_total_supply(ref self: ContractState, from_address: felt252, total_supply: Amount) {
    assert!(
        from_address == self.l1_reward_supplier.read(),
        "{}",
        Error::UNAUTHORIZED_MESSAGE_SENDER,
    );
    ...
}
``` [5](#0-4) 

If the L2 `MintingCurve` contract is upgraded (via its `ReplaceabilityComponent`) and the stored `l1_reward_supplier` address no longer matches the L1 sender, or if the `UPDATE_TOTAL_SUPPLY_SELECTOR` diverges after an upgrade, any in-flight L1→L2 message will revert on L2 and remain permanently unconsumed. Because the sender of the message is the `RewardSupplier` contract itself (not an EOA), only the contract can initiate cancellation — but no such function exists. [6](#0-5) 

---

### Impact Explanation

**Medium — Griefing / damage to users or protocol.**

The ETH fee attached to the `sendMessageToL2` call is non-refundable by the Starknet messaging protocol once the message is stuck. The `tick()` caller (any address) permanently loses the ETH they forwarded. Because `tick()` is permissionless and is expected to be called repeatedly by keepers or protocol participants, the cumulative fee loss across multiple stuck messages can be material. There is no admin escape hatch in the current contract.

---

### Likelihood Explanation

Moderate. The L2 `MintingCurve` contract carries a `ReplaceabilityComponent` that allows governance to upgrade it. Any upgrade that changes the `l1_reward_supplier` storage value or the handler selector would silently strand all in-flight L1→L2 messages. This is a normal operational event (contract upgrades are expected), not a hypothetical attack. Additionally, any future bug in the L2 handler that causes it to revert would produce the same outcome. [7](#0-6) 

---

### Recommendation

Add two governance-gated (or operator-gated) functions to `RewardSupplier` that proxy the Starknet messaging cancellation API:

```solidity
function startCancelTotalSupplyMessage(
    uint256 totalSupply,
    uint256 nonce
) external onlyOperator {
    uint256[] memory payload = new uint256[](1);
    payload[0] = totalSupply;
    messagingContract().startL1ToL2MessageCancellation(
        mintingCurve(),
        UPDATE_TOTAL_SUPPLY_SELECTOR,
        payload,
        nonce
    );
}

function cancelTotalSupplyMessage(
    uint256 totalSupply,
    uint256 nonce
) external onlyOperator {
    uint256[] memory payload = new uint256[](1);
    payload[0] = totalSupply;
    messagingContract().cancelL1ToL2Message(
        mintingCurve(),
        UPDATE_TOTAL_SUPPLY_SELECTOR,
        payload,
        nonce
    );
}
```

This mirrors the pattern described in the [Starknet messaging cancellation documentation](https://docs.starknet.io/architecture-and-concepts/network-architecture/messaging-mechanism/#l2-l1_message_cancellation) and is the same remediation recommended in the original Kakarot finding.

---

### Proof of Concept

1. A keeper calls `RewardSupplier.tick{value: 2 ether}()` while L2→L1 mint requests are pending.
2. `tick()` splits the fee: `msgFee = 1 ether` to the bridge, `msgFee = 1 ether` to `sendMessageToL2`.
3. The L1→L2 message targeting `MintingCurve.update_total_supply` is registered in the Starknet core contract with a 1 ETH fee.
4. Governance upgrades the L2 `MintingCurve` contract; the new implementation stores a different `l1_reward_supplier` value.
5. The sequencer attempts to execute the pending L1→L2 message; the `assert!(from_address == self.l1_reward_supplier.read(), ...)` check fails; the message is not consumed.
6. The keeper attempts to recover the 1 ETH fee. There is no `startL1ToL2MessageCancellation` or `cancelL1ToL2Message` function on `RewardSupplier`. The message sender on-chain is the `RewardSupplier` contract address, so no EOA can initiate cancellation directly. The 1 ETH is permanently lost. [4](#0-3) [8](#0-7)

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

**File:** L1/starkware/starknet/solidity/IStarknetMessaging.sol (L64-91)
```text
    /**
      Starts the cancellation of an L1 to L2 message.
      A message can be canceled messageCancellationDelay() seconds after this function is called.

      Note: This function may only be called for a message that is currently pending and the caller
      must be the sender of the that message.
    */
    function startL1ToL2MessageCancellation(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload,
        uint256 nonce
    ) external returns (bytes32);

    /**
      Cancels an L1 to L2 message, this function should be called at least
      messageCancellationDelay() seconds after the call to startL1ToL2MessageCancellation().
      A message may only be cancelled by its sender.
      If the message is missing, the call will revert.

      Note that the message fee is not refunded.
    */
    function cancelL1ToL2Message(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload,
        uint256 nonce
    ) external returns (bytes32);
```

**File:** src/minting_curve/minting_curve.cairo (L40-47)
```text
    component!(path: ReplaceabilityComponent, storage: replaceability, event: ReplaceabilityEvent);
    component!(path: RolesComponent, storage: roles, event: RolesEvent);
    component!(path: AccessControlComponent, storage: accesscontrol, event: AccessControlEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl ReplaceabilityImpl =
        ReplaceabilityComponent::ReplaceabilityImpl<ContractState>;
```

**File:** src/minting_curve/minting_curve.cairo (L65-72)
```text
        /// Total supply of the token in L1. This is updated by the L1 reward supplier.
        total_supply: Amount,
        /// L1 reward supplier.
        l1_reward_supplier: felt252,
        /// The numerator of the inflation rate. The denominator is `C_DENOM`.
        /// Yearly mint is `(C_NUM / C_DENOM) * sqrt(total_stake * total_supply)`.
        c_num: Inflation,
    }
```

**File:** src/minting_curve/minting_curve.cairo (L118-135)
```text
    #[l1_handler]
    fn update_total_supply(ref self: ContractState, from_address: felt252, total_supply: Amount) {
        assert!(
            from_address == self.l1_reward_supplier.read(),
            "{}",
            Error::UNAUTHORIZED_MESSAGE_SENDER,
        );
        let old_total_supply = self.total_supply.read();
        // Note that the total supply may only increase.
        // Check that total_supply > old_total_supply to handle possible message reordering.
        if total_supply > old_total_supply {
            self.total_supply.write(total_supply);
            self
                .emit(
                    Events::TotalSupplyChanged { old_total_supply, new_total_supply: total_supply },
                );
        }
    }
```
