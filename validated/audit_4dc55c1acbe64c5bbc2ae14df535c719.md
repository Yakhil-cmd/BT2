### Title
Immutable `starkgate_address` in `RewardSupplier` Blocks All Future STRK Reward Deliveries — (File: `src/reward_supplier/reward_supplier.cairo`)

### Summary
The `RewardSupplier` contract stores `starkgate_address` at construction time with no setter function. The `on_receive` callback — the sole entry point for STRK tokens bridged from L1 — hard-gates on this address. If the Starkgate bridge is ever upgraded to a new contract address (a routine Starknet infrastructure event), every incoming STRK transfer will revert, permanently starving the reward pool and freezing all unclaimed staker and delegator yield.

### Finding Description
In `src/reward_supplier/reward_supplier.cairo`, the constructor writes `starkgate_address` once and never exposes a setter:

```cairo
// constructor, line 132
self.starkgate_address.write(starkgate_address);
``` [1](#0-0) 

The only governance-accessible config function exposed by `IRewardSupplierConfig` is `set_block_duration_config`; there is no `set_starkgate_address` or equivalent:

```cairo
impl RewardSupplierConfigImpl of IRewardSupplierConfig<ContractState> {
    fn set_block_duration_config(...) { ... }
    // ← no setter for starkgate_address
}
``` [2](#0-1) 

The `on_receive` callback enforces the frozen address as the only valid caller:

```cairo
assert!(
    get_caller_address() == self.starkgate_address.read(),
    "{}",
    Error::ON_RECEIVE_NOT_FROM_STARKGATE,
);
``` [3](#0-2) 

`on_receive` is the mechanism by which minted STRK arrives on L2 after the L2 contract sends a mint request to L1 via `send_mint_request_to_l1_reward_supplier`. Without a successful `on_receive`, the reward supplier's token balance never grows, `l1_pending_requested_amount` is never decremented, and the contract eventually cannot satisfy `claim_rewards` calls from the staking contract. [4](#0-3) 

The same structural problem applies to `l1_reward_supplier` (the L1 address to which mint-request messages are sent): it is also written once in the constructor with no setter, so an L1-side upgrade would silently route all mint requests to a dead address. [5](#0-4) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Once the Starkgate bridge address changes, every call to `on_receive` from the new bridge reverts. The reward supplier's STRK balance is never replenished. The staking contract calls `claim_rewards` on the reward supplier to pay stakers and delegators; when the supplier's balance is exhausted, those transfers fail. All accumulated, unclaimed STRK rewards for every staker and every pool member are permanently frozen.

### Likelihood Explanation
Starkgate is a live, actively maintained bridge that has undergone upgrades. A future upgrade that changes the bridge's L2 contract address is a realistic operational event, not a theoretical one. No attacker action is required; the freeze is triggered automatically the moment the new bridge address calls `on_receive`.

### Recommendation
1. Add a privileged setter (e.g., `app_governor`-gated) for `starkgate_address` in `IRewardSupplierConfig` and its implementation, mirroring the pattern already used for `set_block_duration_config`.
2. Add an equivalent setter for `l1_reward_supplier` to handle L1-side upgrades.
3. Emit a dedicated event on each change for off-chain monitoring.

### Proof of Concept
1. Deploy `RewardSupplier` with `starkgate_address = BRIDGE_V1`.
2. Starkgate is upgraded; the new bridge address is `BRIDGE_V2`.
3. The L1 reward supplier mints STRK and instructs `BRIDGE_V2` to call `on_receive` on the `RewardSupplier`.
4. `on_receive` asserts `get_caller_address() == BRIDGE_V1` → assertion fails → revert.
5. No STRK arrives in `RewardSupplier`; `unclaimed_rewards` grows but the token balance does not.
6. The staking contract calls `claim_rewards(amount)` → `checked_transfer` fails (insufficient balance).
7. All staker and delegator `claim_rewards` calls revert indefinitely. [6](#0-5)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L111-135)
```text
    #[constructor]
    pub fn constructor(
        ref self: ContractState,
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
        self.minting_curve_dispatcher.contract_address.write(minting_curve_contract);
        self.l1_reward_supplier.write(l1_reward_supplier);
        self.starkgate_address.write(starkgate_address);
        self.avg_block_duration.write(DEFAULT_AVG_BLOCK_DURATION);
        self.block_duration_config.write(DEFAULT_BLOCK_DURATION_CONFIG);
    }
```

**File:** src/reward_supplier/reward_supplier.cairo (L204-220)
```text
        // This function is called by the staking contract, claiming an amount of owed rewards.
        fn claim_rewards(ref self: ContractState, amount: Amount) {
            // Asserts.
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L233-237)
```text
            assert!(
                get_caller_address() == self.starkgate_address.read(),
                "{}",
                Error::ON_RECEIVE_NOT_FROM_STARKGATE,
            );
```

**File:** src/reward_supplier/reward_supplier.cairo (L273-296)
```text
    #[abi(embed_v0)]
    impl RewardSupplierConfigImpl of IRewardSupplierConfig<ContractState> {
        fn set_block_duration_config(
            ref self: ContractState, block_duration_config: BlockDurationConfig,
        ) {
            self.roles.only_app_governor();
            // TODO: Emit event?
            // Assert that block_time_config is valid.
            // TODO: More validations?
            assert!(
                block_duration_config.min_block_duration > 0,
                "{}",
                Error::INVALID_MIN_MAX_BLOCK_DURATION,
            );
            assert!(
                block_duration_config
                    .min_block_duration <= block_duration_config
                    .max_block_duration,
                "{}",
                Error::INVALID_MIN_MAX_BLOCK_DURATION,
            );
            self.block_duration_config.write(block_duration_config);
        }
    }
```

**File:** src/reward_supplier/reward_supplier.cairo (L333-337)
```text
        fn send_mint_request_to_l1_reward_supplier(self: @ContractState) {
            let payload: Span<felt252> = array![self.base_mint_amount.read().into()].span();
            let to_address = self.l1_reward_supplier.read();
            send_message_to_l1_syscall(:to_address, :payload).unwrap_syscall();
        }
```
