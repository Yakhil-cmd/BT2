### Title
Missing Zero-Address Validation in `change_reward_address` Enables Permanent Freezing of Unclaimed Yield - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

### Summary
Both the staking contract and the delegation pool contract allow a staker or pool member to set their `reward_address` to `ContractAddress::zero()`. When rewards are subsequently claimed or distributed via `unstake_action`, the transfer targets address(0), permanently burning the unclaimed yield. This is the direct analog of the referenced bug: just as an owner can remove themselves from a role and lock the system, a staker or pool member can remove their own valid reward destination and permanently lose their yield.

### Finding Description
`change_reward_address` in `src/staking/staking.cairo` performs only one validation — that the new address is not a registered token address:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    self.general_prerequisites();
    assert!(
        !self.does_token_exist(token_address: reward_address),
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    ...
    staker_info.reward_address = reward_address;
    self.write_staker_info(:staker_address, :staker_info);
``` [1](#0-0) 

There is no check that `reward_address != Zero::zero()`. The same omission exists in the pool contract:

```cairo
fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
    assert!(
        self.token_dispatcher.contract_address.read() != reward_address,
        "{}",
        GenericError::REWARD_ADDRESS_IS_TOKEN,
    );
    ...
    pool_member_info.reward_address = reward_address;
    self.write_pool_member_info(:pool_member, :pool_member_info);
``` [2](#0-1) 

When rewards are later distributed, `send_rewards_to_staker` unconditionally transfers to whatever `reward_address` is stored:

```cairo
let reward_address = staker_info.reward_address;
...
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
``` [3](#0-2) 

And in the pool, `claim_rewards` does the same:

```cairo
let reward_address = pool_member_info.reward_address;
...
reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
``` [4](#0-3) 

Critically, `unstake_action` is callable by **any address** (spec: "Any address can execute"), and it internally calls `send_rewards_to_staker` before returning the principal to the staker: [5](#0-4) 

### Impact Explanation
If a staker sets `reward_address` to zero and then calls `unstake_intent`, a third party can call `unstake_action` after the exit window. The `send_rewards_to_staker` call will attempt to transfer accumulated STRK rewards to address(0). Depending on the STRK ERC20 implementation:

- **If transfer to zero succeeds**: all accumulated unclaimed yield is permanently burned — matching the "Permanent freezing of unclaimed yield" impact.
- **If transfer to zero reverts**: `unstake_action` reverts entirely, and the staker's principal stake is temporarily frozen in the contract until they correct the reward address — matching the "Temporary freezing of funds" impact.

The same applies to pool members via `claim_rewards` in `pool.cairo`.

### Likelihood Explanation
A staker or pool member can accidentally pass `ContractAddress::zero()` (e.g., from a misconfigured script, a UI bug, or a default-value error). Once `unstake_intent` is submitted, the exit window is public and any third party can race to call `unstake_action` before the staker corrects the address. The entry path is fully unprivileged — no special role is required. The `change_reward_address` function itself is accessible to any registered staker or pool member.

### Recommendation
Add a non-zero address assertion in both `change_reward_address` implementations:

```cairo
assert!(!reward_address.is_zero(), "REWARD_ADDRESS_IS_ZERO");
```

This mirrors the existing `notSelf` guard pattern used in the referenced L1 `Roles.sol` to prevent self-removal. [6](#0-5) 

### Proof of Concept

1. Staker calls `change_reward_address(ContractAddress::zero())` — passes all current checks since zero is not a registered token address.
2. Staker calls `unstake_intent()` — records exit timestamp.
3. After `exit_wait_window` elapses, any address calls `unstake_action(staker_address)`.
4. Inside `unstake_action`, `send_rewards_to_staker` executes `checked_transfer(recipient: 0x0, amount: unclaimed_rewards)`.
5. Unclaimed STRK yield is sent to address(0) and permanently lost (or the call reverts, locking the principal until the staker corrects the address — but the staker may no longer be able to do so if they have lost key access).

### Citations

**File:** src/staking/staking.cairo (L483-495)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
```

**File:** src/staking/staking.cairo (L517-531)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let old_address = staker_info.reward_address;

            // Update reward_address and commit to storage.
            staker_info.reward_address = reward_address;
            self.write_staker_info(:staker_address, :staker_info);
```

**File:** src/staking/staking.cairo (L1620-1625)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

**File:** src/pool/pool.cairo (L339-366)
```text
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());
```

**File:** src/pool/pool.cairo (L505-517)
```text
        fn change_reward_address(ref self: ContractState, reward_address: ContractAddress) {
            assert!(
                self.token_dispatcher.contract_address.read() != reward_address,
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_address = pool_member_info.reward_address;

            // Update reward_address and commit to storage.
            pool_member_info.reward_address = reward_address;
            self.write_pool_member_info(:pool_member, :pool_member_info);
```

**File:** L1/starkware/solidity/components/Roles.sol (L46-48)
```text
    modifier notSelf(address account) {
        require(account != AccessControl._msgSender(), "CANNOT_PERFORM_ON_SELF");
        _;
```
