Audit Report

## Title
`UpdateSettings` Small-Payload Ingress Messages Classified as `IngressInductionCost::Free`, Enabling Zero-Cost Block Stuffing DoS - (`rs/cycles_account_manager/src/cycles_account_manager.rs`)

## Summary
`UpdateSettings` management canister ingress messages whose argument is ≤ 338 bytes (`MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE`) are classified as `IngressInductionCost::Free` at induction time, bypassing every upfront cycles check in the ingress filter, ingress selector, and valid-set-rule. The post-execution delayed fee is silently discarded on error. An attacker controlling a single canister can flood up to 1,000 `UpdateSettings` messages per block at effectively zero cost, exhausting `MAX_INGRESS_MESSAGES_PER_BLOCK` and denying service to all legitimate users on the subnet.

## Finding Description

**Root cause — `ingress_induction_cost()` returns `Free` for small `UpdateSettings` payloads:**

In `rs/cycles_account_manager/src/cycles_account_manager.rs`, when the ingress targets `IC_00` with method `UpdateSettings` and `arg.len() <= MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE` (338), `paying_canister` is set to `None`, causing the function to return `IngressInductionCost::Free`: [1](#0-0) [2](#0-1) [3](#0-2) 

**All downstream gates are no-ops for `Free`:**

The ingress filter (`should_accept_ingress_message`) only checks cycles when `IngressInductionCost::Fee` is matched; `Free` falls through unconditionally: [4](#0-3) 

The ingress selector's `validate_ingress` explicitly does nothing for `Free`: [5](#0-4) 

The valid-set-rule enqueues `Free` messages directly without any balance check: [6](#0-5) 

**Post-execution fee is silently discarded:**

After `UpdateSettings` executes, the delayed `consume_cycles` call explicitly ignores its error via `_ignore_error`. If the canister is out of cycles, the fee is dropped and the message was processed for free end-to-end: [7](#0-6) 

**Block capacity limit that the attacker exploits:** [8](#0-7) 

The ingress selector enforces this cap at line 510, but the attacker's `Free` messages count toward it just like any other message, filling all 1,000 slots.

## Impact Explanation

An attacker can continuously exhaust `MAX_INGRESS_MESSAGES_PER_BLOCK` (1,000) every round with zero-cost `UpdateSettings` messages, preventing all legitimate ingress from being included in blocks on the targeted subnet. This is a concrete, sustained subnet availability impact — not raw volumetric DDoS, but a protocol-level resource exhaustion caused by a missing fee gate. This matches the **High ($2,000–$10,000)** impact: *Application/platform-level DoS or subnet availability impact not based on raw volumetric DDoS.*

## Likelihood Explanation

The only precondition is controlling one canister on an application subnet, which is a routine, low-cost operation available to any principal. No privileged role, no threshold corruption, no external dependency. The attack is fully automatable, repeatable every round, and self-sustaining if the canister is drained of cycles (the post-execution fee is silently dropped). The 338-byte threshold is easily satisfied by a minimal `UpdateSettingsArgs` Candid payload.

## Recommendation

1. **Remove the `Free` classification for `UpdateSettings`**: Charge the induction cost upfront at the ingress selector and valid-set-rule, exactly as every other management canister method. To preserve the "unfreeze" use-case, relax only the freeze-threshold check (allow the fee to be charged even when the canister is below the freeze threshold), rather than waiving the fee entirely.
2. **Do not silently ignore the post-execution `consume_cycles` error**: At minimum, log it as a critical metric so fee evasion is observable.
3. **Account for `Free`-but-delayed-charge messages in the ingress selector's `cycles_needed` map**: Prevent a block from being stuffed with messages whose aggregate delayed cost exceeds what the canister can pay.

## Proof of Concept

1. Attacker creates canister `C` on an application subnet with a minimal (or zero) cycles balance.
2. Attacker constructs a minimal `UpdateSettingsArgs` Candid payload (e.g., `freezing_threshold = 1`) encoded to ≤ 338 bytes.
3. Attacker submits 1,000 distinct `UpdateSettings` ingress messages (varying the nonce/expiry) targeting `C` via the boundary node.
4. `ingress_induction_cost()` returns `IngressInductionCost::Free` for each; all 1,000 pass the ingress filter and selector with zero cycles deducted.
5. The ingress selector builds a block payload containing all 1,000 messages, exhausting `MAX_INGRESS_MESSAGES_PER_BLOCK`.
6. Legitimate user transactions submitted in the same round are excluded from the block.
7. After execution, the post-execution fee on `C` is either negligible or silently dropped if `C` is out of cycles.
8. Attacker repeats every round indefinitely.

A deterministic integration test using PocketIC or a local replica can confirm this by: (a) submitting 1,000 such messages from a single controller principal, (b) asserting all are accepted by the ingress filter and selector, (c) asserting the resulting block payload contains all 1,000 messages, and (d) asserting a concurrently submitted legitimate message from a different principal is excluded.

### Citations

**File:** rs/cycles_account_manager/src/cycles_account_manager.rs (L43-45)
```rust
/// Maximum payload size of a management call to update_settings
/// overriding the canister's freezing threshold.
const MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE: usize = 338;
```

**File:** rs/cycles_account_manager/src/cycles_account_manager.rs (L570-595)
```rust
                if let Ok(Method::UpdateSettings) = Method::from_str(ingress.method_name()) {
                    // The fee for `UpdateSettings` with small payload is charged after
                    // applying the settings to allow users to unfreeze canisters
                    // after accidentally setting the freezing threshold too high.
                    if self.is_delayed_ingress_induction_cost(ingress.arg()) {
                        None
                    } else {
                        effective_canister_id
                    }
                } else {
                    effective_canister_id
                }
            }
            // A message to a canister is always paid for by the receiving canister.
            false => Some(ingress.canister_id()),
        };

        match paying_canister {
            Some(paying_canister) => {
                let cost = self.ingress_induction_cost_from_bytes(raw_bytes, subnet_cycles_config);
                IngressInductionCost::Fee {
                    payer: paying_canister,
                    cost: cost.real(),
                }
            }
            None => IngressInductionCost::Free,
```

**File:** rs/cycles_account_manager/src/cycles_account_manager.rs (L1379-1381)
```rust
    pub fn is_delayed_ingress_induction_cost(&self, arg: &[u8]) -> bool {
        arg.len() <= MAX_DELAYED_INGRESS_COST_PAYLOAD_SIZE
    }
```

**File:** rs/execution_environment/src/execution_environment.rs (L1043-1052)
```rust
                                // This call may fail with `CanisterOutOfCyclesError`,
                                // which is not actionable at this point.
                                let _ignore_error = self.cycles_account_manager.consume_cycles(
                                    &mut canister.system_state,
                                    memory_usage,
                                    message_memory_usage,
                                    induction_cost,
                                    subnet_cycles_config,
                                    false, // we ignore the error anyway => no need to reveal top up balance
                                );
```

**File:** rs/execution_environment/src/execution_environment.rs (L3351-3373)
```rust
            if let IngressInductionCost::Fee { payer, cost } = induction_cost {
                let paying_canister = canister(payer)?;
                let reveal_top_up = paying_canister
                    .controllers()
                    .contains(&ingress.sender().get());
                if let Err(err) = self
                    .cycles_account_manager
                    .can_withdraw_cycles_with_threshold(
                        &paying_canister.system_state,
                        cost,
                        paying_canister.memory_usage(),
                        paying_canister.message_memory_usage(),
                        paying_canister.system_state.reserved_balance(),
                        subnet_cycles_config,
                        reveal_top_up,
                    )
                {
                    return Err(UserError::new(
                        ErrorCode::CanisterOutOfCycles,
                        err.to_string(),
                    ));
                }
            }
```

**File:** rs/ingress_manager/src/ingress_selector.rs (L592-594)
```rust
            IngressInductionCost::Free => {
                // Do nothing.
            }
```

**File:** rs/messaging/src/scheduling/valid_set_rule.rs (L287-291)
```rust
            IngressInductionCost::Free => {
                // Only subnet methods can be free. These are enqueued directly.
                assert!(ingress.is_addressed_to_subnet());
                state.push_ingress(ingress)
            }
```

**File:** rs/limits/src/lib.rs (L78-78)
```rust
pub const MAX_INGRESS_MESSAGES_PER_BLOCK: u64 = 1000;
```
