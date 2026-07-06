### Title
Insufficient `msg.value` Validation in `tick()` Enables Front-Running to Permanently Freeze Minted Reward Tokens — (`L1/starkware/solidity/stake/RewardSupplier.sol`)

---

### Summary

The `tick()` function in `RewardSupplier.sol` is permissionlessly callable (`external payable`) with any `msg.value`, including dust amounts. It consumes pending L2→L1 mint-request messages, mints STRK tokens, then forwards them to L2 via `depositWithMessage{value: msg.value/2}` and sends a total-supply update via `sendMessageToL2{value: msg.value - msgFee}`. There is no minimum-fee guard. An attacker can front-run a legitimate `tick()` call with a near-zero `msg.value`, causing the L2→L1 messages to be irreversibly consumed and tokens to be minted, while the resulting L1→L2 bridge message carries a fee too small for the Starknet sequencer to process. The minted tokens become stuck in the StarkGate bridge with no recovery path inside `RewardSupplier`, permanently freezing the unclaimed yield for all stakers.

---

### Finding Description

`tick()` performs three sequential, irreversible side-effects in one transaction:

1. **Consume** up to `MAX_MESSAGES_TO_PROCESS_PER_TICK` (5) L2→L1 mint-request messages via `consumeMessageFromL2`.
2. **Mint** `TOKENS_PER_MINT_REQUEST × numMsgsToConsume` (up to `6 500 000 STRK`) via `mintManager().mintRequest()`.
3. **Bridge** the minted tokens to L2 via `bridge().depositWithMessage{value: msg.value/2}(...)` and send a total-supply update via `messagingContract().sendMessageToL2{value: msg.value - msgFee}(...)`.

The fee split is:

```solidity
uint256 msgFee = msg.value / 2;                          // line 125
bridge().depositWithMessage{value: msgFee}(...);          // line 126
msgFee = msg.value - msgFee;                             // line 135
messagingContract().sendMessageToL2{value: msgFee}(...); // line 137
```

There is no `require(msg.value >= MIN_FEE, ...)` guard anywhere in the function.

The Starknet Core contract's `sendMessageToL2` requires `msg.value > 0` to register an L1→L2 message, but it does **not** enforce a minimum fee sufficient for sequencer execution. Calling `tick()` with `msg.value = 2 wei` results in both calls receiving 1 wei each — enough to avoid an on-chain revert, but far below the fee threshold the Starknet sequencer needs to include the message in an L2 block. The bridge message is stored on-chain but never executed on L2, leaving the minted STRK permanently locked in the StarkGate bridge contract. `RewardSupplier` has no mechanism to cancel the bridge message or recover the tokens.

---

### Impact Explanation

Each successful low-fee `tick()` call silently discards up to **6 500 000 STRK** (5 × 1 300 000 STRK) of freshly minted rewards. Because the L2→L1 messages are consumed, the L2 `RewardSupplier` believes the mint was fulfilled and decrements `l1_pending_requested_amount` when `on_receive` is eventually called — but `on_receive` is never called because the bridge message is never processed. The reward pipeline stalls: stakers and delegators cannot claim the yield that was supposed to be bridged, constituting **permanent freezing of unclaimed yield** (High impact).

---

### Likelihood Explanation

- `tick()` is a public, permissionless function explicitly designed to be called by "any account" (confirmed in the spec diagram at `docs/spec.md` line 555).
- Front-running on Ethereum L1 is trivial via MEV bots or direct gas-price manipulation.
- The attacker's cost is negligible: 2 wei + L1 gas for the `tick()` call.
- The attack can be repeated every time new L2→L1 mint-request messages accumulate, continuously draining the reward pipeline.

---

### Recommendation

Add a minimum-fee guard before the bridge and messaging calls. The guard should ensure each sub-call receives at least the minimum fee required by the Starknet Core contract:

```solidity
function tick() external payable {
    (uint256 amountToMint, uint256 numMsgsToConsume) = requiredMinting();
    if (amountToMint > 0) {
        uint256 minFeePerMsg = messagingContract().getMaxL1MsgFee(); // or a protocol-defined constant
        require(msg.value >= 2 * minFeePerMsg, "INSUFFICIENT_FEE");

        // ... existing logic ...
        uint256 msgFee = msg.value / 2;
        bridge().depositWithMessage{value: msgFee}(...);
        msgFee = msg.value - msgFee;
        messagingContract().sendMessageToL2{value: msgFee}(...);
    }
}
```

Alternatively, restrict `tick()` to a trusted keeper role, or require the caller to supply a fee that is validated against a configurable minimum.

---

### Proof of Concept

1. L2 `RewardSupplier` sends 3 mint-request messages to L1 (normal protocol operation).
2. A legitimate keeper prepares a `tick()` call with `msg.value = 0.01 ETH`.
3. Attacker observes the pending transaction in the mempool and submits `tick()` with `msg.value = 2 wei` and a higher gas price.
4. Attacker's transaction executes first:
   - `consumeMessageFromL2` × 3 — messages consumed, counter decremented.
   - `mintManager().mintRequest(token, 3_900_000e18)` — 3 900 000 STRK minted to `RewardSupplier`.
   - `bridge().depositWithMessage{value: 1}(token, 3_900_000e18, mintDestination, [])` — bridge message registered with 1 wei fee; sequencer ignores it.
   - `messagingContract().sendMessageToL2{value: 1}(mintingCurve, UPDATE_TOTAL_SUPPLY_SELECTOR, [totalSupply])` — total-supply update registered with 1 wei fee; also ignored.
5. Legitimate keeper's `tick()` call executes: `requiredMinting()` returns `(0, 0)` because all messages are consumed; function exits early with no effect.
6. 3 900 000 STRK sit permanently in the StarkGate bridge. `on_receive` is never called on L2. Stakers' unclaimed yield is frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L93-105)
```text
    function requiredMinting() public view returns (uint256, uint256) {
        uint256[] memory messagePayload = new uint256[](1);
        messagePayload[0] = TOKENS_PER_MINT_REQUEST;

        bytes32 msgHash = l2ToL1MsgHash(mintRequestSource(), address(this), messagePayload);
        // Limit the number of msgs to consume to limit.
        uint256 numMsgsToConsume = Math.min(
            messagingContract().l2ToL1Messages(msgHash),
            MAX_MESSAGES_TO_PROCESS_PER_TICK
        );

        return (TOKENS_PER_MINT_REQUEST * numMsgsToConsume, numMsgsToConsume);
    }
```

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

**File:** L1/starkware/starknet/solidity/IStarknetMessaging.sol (L43-53)
```text
    /**
      Sends a message to an L2 contract.
      This function is payable, the payed amount is the message fee.

      Returns the hash of the message and the nonce of the message.
    */
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32, uint256);
```
