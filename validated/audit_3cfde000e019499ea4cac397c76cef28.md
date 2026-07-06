### Title
Hardcoded `starkgate_address` Check in `on_receive` Can Permanently Block Reward Token Delivery — (File: `src/reward_supplier/reward_supplier.cairo`)

### Summary
The `on_receive` callback in `RewardSupplier` asserts that the caller is exactly the stored `starkgate_address`. This address is set once at construction with no update mechanism. If StarkGate is redeployed or upgraded to a new address, every subsequent L1→L2 reward deposit will revert, permanently blocking the delivery of minted STRK rewards to the protocol and freezing unclaimed yield for all stakers.

### Finding Description
`RewardSupplier.on_receive` is the L1→L2 callback invoked by the StarkGate bridge when the L1 `MintManager` deposits minted STRK tokens into the protocol. The function enforces:

```cairo
// src/reward_supplier/reward_supplier.cairo lines 233-237
assert!(
    get_caller_address() == self.starkgate_address.read(),
    "{}",
    Error::ON_RECEIVE_NOT_FROM_STARKGATE,
);
```

The `starkgate_address` field is written exactly once, in the constructor:

```cairo
// line 132
self.starkgate_address.write(starkgate_address);
```

Neither `IRewardSupplierConfig` nor the upgrade EIC (`src/reward_supplier/eic.cairo`) exposes any setter for `starkgate_address`. If StarkGate is redeployed at a new address (as has occurred historically with StarkGate upgrades), the new bridge will call `on_receive` from a different `caller_address`, the assert will panic, and the entire deposit transaction will revert. Because Starknet L1→L2 messages that revert on L2 are not consumed, the tokens remain locked in the L1 bridge and `l1_pending_requested_amount` is never decremented, causing the accounting to diverge permanently.

### Impact Explanation
Once the stale address causes `on_receive` to revert, the `RewardSupplier` can no longer receive minted STRK from L1. Its on-chain balance will not grow to cover `unclaimed_rewards`. When the staking contract calls `claim_rewards`, the ERC-20 transfer will fail (insufficient balance), blocking reward payouts to every staker and delegator. This is **freezing of unclaimed yield** for the entire protocol until governance deploys a contract upgrade — which itself requires a time-locked governance process.

Impact: **High — Permanent/temporary freezing of unclaimed yield for all stakers.**

### Likelihood Explanation
StarkGate has undergone address-changing upgrades before. The `starkgate_address` has no on-chain update path, so any such upgrade immediately breaks the reward flow. The condition is entirely outside the protocol's control and requires no attacker: normal protocol operation (L1 mint request → StarkGate deposit → `on_receive`) triggers the revert automatically after a bridge upgrade.

### Recommendation
1. Add a privileged setter (e.g., `app_governor`-gated) for `starkgate_address` in `IRewardSupplierConfig`, mirroring the pattern already used for `set_block_duration_config`.
2. Alternatively, remove the caller check entirely and rely solely on the `l2_token` and `depositor` checks, since the comment on line 229 already acknowledges that any depositor is acceptable.
3. At minimum, include `starkgate_address` as an updatable field in future EIC migrations.

### Proof of Concept

**Normal flow (working):**
1. L2 `RewardSupplier.update_unclaimed_rewards_from_staking_contract` → `request_funds` → `send_mint_request_to_l1_reward_supplier` sends L2→L1 message.
2. L1 `MintManager` receives message, calls `StarkGate.depositWithMessage(recipient=RewardSupplier, amount=X)`.
3. StarkGate (at stored address) calls `RewardSupplier.on_receive(...)` → assert passes → `l1_pending_requested_amount` decremented.

**Post-StarkGate-upgrade (broken):**
1. Same steps 1–2, but StarkGate is now deployed at `NEW_STARKGATE_ADDR ≠ starkgate_address`.
2. `on_receive` is called from `NEW_STARKGATE_ADDR`.
3. `assert!(get_caller_address() == self.starkgate_address.read(), ...)` → **panics**.
4. L1→L2 message is not consumed; tokens remain in L1 bridge.
5. `l1_pending_requested_amount` stays inflated; `RewardSupplier` balance never grows.
6. All subsequent `claim_rewards` calls from the staking contract fail due to insufficient balance → **all staker rewards frozen**.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L131-132)
```text
        self.l1_reward_supplier.write(l1_reward_supplier);
        self.starkgate_address.write(starkgate_address);
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

**File:** src/reward_supplier/interface.cairo (L85-103)
```text
#[starknet::interface]
pub trait IRewardSupplierConfig<TContractState> {
    /// Sets the block duration configuration.
    ///
    /// #### Preconditions:
    /// - `block_duration_config.min_block_duration > 0`
    /// - `block_duration_config.min_block_duration <= block_duration_config.max_block_duration`
    ///
    /// #### Errors:
    /// - [`ONLY_APP_GOVERNOR`](AccessErrors::ONLY_APP_GOVERNOR)
    /// -
    /// [`INVALID_MIN_MAX_BLOCK_DURATION`](staking::reward_supplier::errors::Error::INVALID_MIN_MAX_BLOCK_DURATION)
    ///
    /// #### Access control:
    /// Only app governor.
    fn set_block_duration_config(
        ref self: TContractState, block_duration_config: BlockDurationConfig,
    );
}
```

**File:** src/reward_supplier/eic.cairo (L1-43)
```text
/// An External Initializer Contract to upgrade a reward supplier contract.
/// This EIC is used to upgrade the reward supplier contract from V2 (BTC) to V3.
#[starknet::contract]
mod RewardSupplierEIC {
    use staking::reward_supplier::errors::Error;
    use staking::reward_supplier::interface::BlockDurationConfig;
    use starknet::storage::StoragePointerWriteAccess;
    use starkware_utils::components::replaceability::interface::IEICInitializable;

    #[storage]
    struct Storage {
        // --- New fields ---
        /// Average block duration in units of 1 / BLOCK_DURATION_SCALE seconds.
        avg_block_duration: u64,
        /// Configuration for block duration calculation.
        block_duration_config: BlockDurationConfig,
    }

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
