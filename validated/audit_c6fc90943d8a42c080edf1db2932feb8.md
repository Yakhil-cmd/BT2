### Title
Unpermissioned `exit_delegation_pool_action` Enables Front-Running to Block Pool Member Switches — (File: `src/pool/pool.cairo`)

---

### Summary

`exit_delegation_pool_action` in the Pool contract accepts a `pool_member` address as a parameter but performs **no check** that the caller is the pool member (or any authorized party). Any address can trigger the exit action for any pool member once the exit window has passed. This mirrors the Scroll `dropMessage`/`replayMessage` pattern exactly: a user who has signalled an intent has two possible follow-up actions, and an adversary can force the undesired one.

---

### Finding Description

After calling `exit_delegation_pool_intent`, a pool member has two mutually exclusive follow-up paths once the exit window elapses:

1. **`exit_delegation_pool_action(pool_member)`** — returns the `unpool_amount` as tokens to the pool member and clears `unpool_time`.
2. **`switch_delegation_pool(to_staker, to_pool, amount)`** — moves the `unpool_amount` seamlessly to a new pool without a second exit window.

`exit_delegation_pool_action` contains no caller restriction: [1](#0-0) 

The function only checks that the pool member exists, has a pending intent, and that the exit window has elapsed. No `assert!(get_caller_address() == pool_member, ...)` is present.

When `exit_delegation_pool_action` executes, it clears `unpool_time` to `None`: [2](#0-1) 

`switch_delegation_pool`, however, requires `unpool_time.is_some()` as a hard precondition: [3](#0-2) 

Once an adversary calls `exit_delegation_pool_action` first, `unpool_time` is `None` and the pool member's subsequent `switch_delegation_pool` call panics with `MISSING_UNDELEGATE_INTENT`.

The same pattern exists in `unstake_action` in the Staking contract — it also accepts `staker_address` as a parameter with no caller check — but the pool-level variant is more impactful because it forecloses the switch path entirely: [4](#0-3) 

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users.**

The pool member is forced to exit the pool rather than switch to their preferred pool. Consequences:

- The seamless `switch_delegation_pool` path is permanently blocked for that intent cycle.
- The pool member must re-enter the target pool from scratch via `enter_delegation_pool`, paying extra gas and going through a new K-epoch activation delay before their stake counts toward rewards.
- During the gap between forced exit and re-entry, the `unpool_amount` earns no staking rewards.

No funds are permanently lost (the `unpool_amount` is returned to the pool member), so this does not reach High/Critical. It squarely fits the **Medium: Griefing** category.

---

### Likelihood Explanation

- The entry point (`exit_delegation_pool_action`) is a public, permissionless function callable by any EOA or contract.
- On Starknet the sequencer orders transactions; a well-resourced adversary (including the sequencer itself) can observe a pending `switch_delegation_pool` and insert `exit_delegation_pool_action` ahead of it.
- Even without mempool visibility, an adversary can simply call `exit_delegation_pool_action` at any point after the exit window passes, before the pool member calls `switch_delegation_pool`. No timing precision is required.
- Cost to the attacker: one transaction fee.

---

### Recommendation

Add a caller restriction to `exit_delegation_pool_action` so that only the pool member (or their registered `reward_address`) can trigger the exit:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let caller = get_caller_address();
    let pool_member_info = self.internal_pool_member_info(:pool_member);
    assert!(
        caller == pool_member || caller == pool_member_info.reward_address,
        "{}",
        Error::CALLER_CANNOT_EXIT_POOL,
    );
    // ... rest of function
```

Apply the same fix to `unstake_action` in `src/staking/staking.cairo` (line 483).

---

### Proof of Concept

```
1. Pool member (Alice) calls exit_delegation_pool_intent(amount=100)
   → pool_member_info.unpool_time = Some(T_exit)
   → pool_member_info.unpool_amount = 100

2. Time advances past T_exit.

3. Alice decides to switch to a better pool and submits:
     switch_delegation_pool(to_staker=B, to_pool=P2, amount=100)
   [transaction is pending / not yet included]

4. Adversary (Bob) observes Alice's intent and calls:
     exit_delegation_pool_action(pool_member=Alice)
   → pool_member_info.unpool_time = None   ← cleared
   → pool_member_info.unpool_amount = 0    ← cleared
   → 100 tokens transferred to Alice

5. Alice's switch_delegation_pool transaction executes:
     assert!(pool_member_info.unpool_time.is_some(), ...)
     → PANICS: "MISSING_UNDELEGATE_INTENT"

6. Alice must now call enter_delegation_pool on P2 from scratch,
   waiting another K epochs before her stake is active and earning rewards.
```

Root cause: `src/pool/pool.cairo` line 295 — `exit_delegation_pool_action` has no `get_caller_address()` restriction.
Blocked path: `src/pool/pool.cairo` line 389-393 — `switch_delegation_pool` requires `unpool_time.is_some()`. [5](#0-4) [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L295-333)
```text
        fn exit_delegation_pool_action(
            ref self: ContractState, pool_member: ContractAddress,
        ) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberExitAction {
                        pool_member, unpool_amount: pool_member_info.unpool_amount,
                    },
                );

            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
        }
```

**File:** src/pool/pool.cairo (L379-394)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
            assert!(amount <= pool_member_info.unpool_amount, "{}", GenericError::AMOUNT_TOO_HIGH);
```

**File:** src/staking/staking.cairo (L483-490)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
```
