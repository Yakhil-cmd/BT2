### Title
Stakers Can Bypass Exit Wait Window by Pre-Registering Intent When `exit_wait_window == 0` - (File: src/staking/staking.cairo)

### Summary
`set_exit_wait_window` enforces only an upper bound on the exit wait window, allowing it to be set to zero. When `exit_wait_window == 0`, `unstake_intent()` records `unstake_time = Time::now()`. Because the protocol explicitly does not retroactively update already-registered intents when the window is later increased, any staker who called `unstake_intent()` while the window was zero can call `unstake_action()` immediately after the window is re-enabled, bypassing the cooldown entirely.

### Finding Description
`set_exit_wait_window` in `src/staking/staking.cairo` validates only an upper bound:

```rust
assert!(exit_wait_window <= MAX_EXIT_WAIT_WINDOW, "{}", Error::ILLEGAL_EXIT_DURATION);
``` [1](#0-0) 

There is no lower bound check, so `exit_wait_window = TimeDelta { seconds: 0 }` is accepted. The interface comment for `set_exit_wait_window` even notes "The exit wait window must be at least K epochs," but this is never enforced in code. [2](#0-1) 

When `unstake_intent()` is called, the unstake timestamp is computed as:

```rust
let unstake_time = Time::now().add(delta: self.exit_wait_window.read());
``` [3](#0-2) 

If `exit_wait_window == 0`, then `unstake_time = Time::now()`. The action check in `unstake_action()` is:

```rust
assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
``` [4](#0-3) 

This passes immediately in the same block (or any future block). The same pattern applies to delegators via `compute_unpool_time`, which returns `Time::now().add(delta: exit_wait_window)` when the staker is active: [5](#0-4) 

The protocol's own documentation confirms that intent timestamps are never retroactively updated when the window changes:

> "Changing the exit wait window does not retroactively affect validators/delegators who already submitted an exit_intent call." [6](#0-5) 

### Impact Explanation
The exit wait window is the protocol's primary mechanism to ensure stakers cannot rapidly exit (e.g., to front-run a slashing event or destabilize consensus participation). A staker who pre-registers an intent during a zero-window period retains a permanently valid "instant exit" ticket that survives any subsequent window increase. This undermines the security model of the exit wait window for those stakers, constituting **griefing with damage to the protocol** (Medium).

### Likelihood Explanation
The token admin can set `exit_wait_window` to zero at any time (e.g., during an emergency or migration). Any staker monitoring on-chain state can observe this and call `unstake_intent()` in the same block. When the admin later restores the window, those stakers are permanently exempt. Likelihood is **Medium**: requires the admin to set the window to zero, which is a realistic operational scenario.

### Recommendation
Add a minimum lower bound check in `set_exit_wait_window`, enforcing that `exit_wait_window >= K_EPOCHS_DURATION` (consistent with the documented invariant). Additionally, consider reverting `unstake_intent()` when `exit_wait_window == 0`, mirroring the recommendation in the reference report.

```rust
fn set_exit_wait_window(ref self: ContractState, exit_wait_window: TimeDelta) {
    self.roles.only_token_admin();
    assert!(exit_wait_window >= MIN_EXIT_WAIT_WINDOW, "{}", Error::ILLEGAL_EXIT_DURATION);
    assert!(exit_wait_window <= MAX_EXIT_WAIT_WINDOW, "{}", Error::ILLEGAL_EXIT_DURATION);
    ...
}
```

### Proof of Concept
1. Token admin calls `set_exit_wait_window(TimeDelta { seconds: 0 })` — accepted because only the upper bound is checked.
2. Staker calls `unstake_intent()` → `unstake_time = Time::now() + 0 = Time::now()`.
3. Token admin calls `set_exit_wait_window(TimeDelta { seconds: WEEK * 3 })` to re-enable the cooldown.
4. Staker immediately calls `unstake_action()` in the next block. The check `Time::now() >= unstake_time` passes because `unstake_time` was set to a past timestamp. Funds are returned with zero waiting period, bypassing the newly enforced three-week window.

The same attack path applies to delegators: `exit_delegation_pool_intent()` → `compute_unpool_time()` → `Time::now() + 0` → immediate `exit_delegation_pool_action()`. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L441-442)
```text
            let unstake_time = Time::now().add(delta: self.exit_wait_window.read());
            staker_info.unstake_time = Option::Some(unstake_time);
```

**File:** src/staking/staking.cairo (L490-490)
```text
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
```

**File:** src/staking/staking.cairo (L1281-1283)
```text
        fn set_exit_wait_window(ref self: ContractState, exit_wait_window: TimeDelta) {
            self.roles.only_token_admin();
            assert!(exit_wait_window <= MAX_EXIT_WAIT_WINDOW, "{}", Error::ILLEGAL_EXIT_DURATION);
```

**File:** src/staking/interface.cairo (L247-251)
```text
    /// Note: Changing the exit wait window does not retroactively affect validators/delegators
    /// who already submitted an exit_intent call. They remain governed by
    /// the old exit wait window when calling exit_action.
    /// Note: The exit wait window must be at least K epochs.
    fn set_exit_wait_window(ref self: TContractState, exit_wait_window: TimeDelta);
```

**File:** src/staking/objects.cairo (L631-638)
```text
    fn compute_unpool_time(
        self: @InternalStakerInfoLatest, exit_wait_window: TimeDelta,
    ) -> Timestamp {
        if let Option::Some(unstake_time) = *self.unstake_time {
            return max(unstake_time, Time::now());
        }
        Time::now().add(delta: exit_wait_window)
    }
```

**File:** src/pool/pool.cairo (L256-272)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
```
