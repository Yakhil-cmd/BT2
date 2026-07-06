### Title
Hardcoded `TOKENS_PER_MINT_REQUEST` on L1 Permanently Breaks Mint-Request Consumption When L2 `base_mint_amount` Diverges - (`L1/starkware/solidity/stake/RewardSupplier.sol`)

### Summary

The L1 `RewardSupplier` hardcodes the mint-request payload value as `TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18`. The L2 `RewardSupplier` sends `base_mint_amount` as the payload in every L2→L1 mint-request message. The L1 contract uses its hardcoded constant to compute the message hash it looks up in the Starknet messaging contract. If `base_mint_amount` on L2 ever differs from `TOKENS_PER_MINT_REQUEST` on L1, the hash never matches, `tick()` silently does nothing, and the reward-supply pipeline is permanently broken.

### Finding Description

**L1 side — hardcoded constant used for message-hash lookup:** [1](#0-0) 

```solidity
uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;
```

`requiredMinting()` builds the expected message hash using this constant: [2](#0-1) 

`tick()` then consumes messages using the same hardcoded value: [3](#0-2) 

**L2 side — configurable `base_mint_amount` written into the message payload:** [4](#0-3) 

`base_mint_amount` is a constructor parameter with no on-chain setter: [5](#0-4) 

The EIC upgrade contract (V2→V3) only initialises `avg_block_duration` and `block_duration_config`; it does not touch `base_mint_amount`: [6](#0-5) 

There is therefore **no on-chain enforcement** that `base_mint_amount == TOKENS_PER_MINT_REQUEST`. A deployment with a mismatched value, or a future upgrade path that needs to change `base_mint_amount`, silently breaks the entire minting pipeline.

### Impact Explanation

When `base_mint_amount ≠ TOKENS_PER_MINT_REQUEST`:

1. L2 emits mint-request messages with payload `[base_mint_amount]`.
2. L1 `requiredMinting()` looks up messages with payload `[TOKENS_PER_MINT_REQUEST]` — hash mismatch → `numMsgsToConsume = 0`.
3. `tick()` does nothing; no tokens are minted or bridged to L2.
4. `l1_pending_requested_amount` on L2 grows without bound; the reward-supplier balance drains to zero.
5. `claim_rewards` reverts with `AMOUNT_TOO_HIGH` for every staker and delegator.

This is **permanent freezing of unclaimed yield** — matching the High-severity impact tier.

### Likelihood Explanation

- `base_mint_amount` is a free constructor argument; there is no compile-time or runtime check that it equals `TOKENS_PER_MINT_REQUEST`.
- The EIC upgrade mechanism cannot correct a mismatch post-deployment without a full proxy upgrade of the L1 contract.
- Any operator deploying the L2 contract with a different denomination (e.g., a different token precision or a deliberate parameter change) silently triggers the freeze.

### Recommendation

1. **Add a cross-chain consistency check**: emit `base_mint_amount` in a deployment event and verify it equals `TOKENS_PER_MINT_REQUEST` in the L1 `validateInitData`.
2. **Or make `TOKENS_PER_MINT_REQUEST` a storage variable** on L1 that is set during initialisation and can be updated by governance, mirroring the L2 `base_mint_amount`.
3. **Add an invariant assertion** in `tick()`:
   ```solidity
   require(messagePayload[0] == TOKENS_PER_MINT_REQUEST, "PAYLOAD_MISMATCH");
   ```
   and expose a governance setter so both sides can be kept in sync.

### Proof of Concept

1. Deploy L2 `RewardSupplier` with `base_mint_amount = 1_000_000 * 10**18` (≠ `1_300_000 * 10**18`).
2. Staking rewards accumulate; `update_unclaimed_rewards_from_staking_contract` triggers `request_funds`, which calls `send_mint_request_to_l1_reward_supplier` with payload `[1_000_000e18]`.
3. Call `tick()` on L1 with sufficient ETH. `requiredMinting()` computes the hash for payload `[1_300_000e18]` — no matching messages exist → returns `(0, 0)`.
4. `tick()` exits without minting or bridging anything.
5. Repeat indefinitely: `l1_pending_requested_amount` grows, L2 balance drains, all `claim_rewards` calls revert.

### Citations

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L10-10)
```text
uint256 constant TOKENS_PER_MINT_REQUEST = 1_300_000 * 10**18;
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L93-104)
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
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L113-119)
```text
            uint256[] memory messagePayload = new uint256[](1);
            messagePayload[0] = TOKENS_PER_MINT_REQUEST;

            // Consume the mintRequest messages.
            for (uint256 i = 0; i < numMsgsToConsume; i++) {
                messagingContract().consumeMessageFromL2(mintRequestSource(), messagePayload);
            }
```

**File:** src/reward_supplier/reward_supplier.cairo (L114-129)
```text
        base_mint_amount: Amount,
        minting_curve_contract: ContractAddress,
        staking_contract: ContractAddress,
        l1_reward_supplier: felt252,
        starkgate_address: ContractAddress,
        governance_admin: ContractAddress,
    ) {
        let token_address = STRK_TOKEN_ADDRESS;
        self.roles.initialize(:governance_admin);
        self.staking_contract.write(staking_contract);
        self.token_dispatcher.contract_address.write(token_address);
        // Initialize unclaimed_rewards with 1 STRK to make up for round ups of pool rewards
        // calculation in the staking contract.
        self.unclaimed_rewards.write(STRK_IN_FRIS);
        self.l1_pending_requested_amount.write(Zero::zero());
        self.base_mint_amount.write(base_mint_amount);
```

**File:** src/reward_supplier/reward_supplier.cairo (L333-337)
```text
        fn send_mint_request_to_l1_reward_supplier(self: @ContractState) {
            let payload: Span<felt252> = array![self.base_mint_amount.read().into()].span();
            let to_address = self.l1_reward_supplier.read();
            send_message_to_l1_syscall(:to_address, :payload).unwrap_syscall();
        }
```

**File:** src/reward_supplier/eic.cairo (L19-43)
```text
    /// Expected data : [avg_block_duration, min_block_duration, max_block_duration]
    #[abi(embed_v0)]
    impl EICInitializable of IEICInitializable<ContractState> {
        fn eic_initialize(ref self: ContractState, eic_init_data: Span<felt252>) {
            assert(eic_init_data.len() == 3, 'EXPECTED_DATA_LENGTH_3');
            let avg_block_duration: u64 = (*eic_init_data[0]).try_into().unwrap();
            let min_block_duration: u64 = (*eic_init_data[1]).try_into().unwrap();
            let max_block_duration: u64 = (*eic_init_data[2]).try_into().unwrap();

            // Validate values.
            assert!(
                min_block_duration <= avg_block_duration
                    && avg_block_duration <= max_block_duration,
                "{}",
                'INVALID_AVG_BLOCK_DURATION',
            );
            assert!(min_block_duration > 0, "{}", Error::INVALID_MIN_MAX_BLOCK_DURATION);

            // Set values.
            self.avg_block_duration.write(avg_block_duration);
            self
                .block_duration_config
                .write(BlockDurationConfig { min_block_duration, max_block_duration });
        }
    }
```
