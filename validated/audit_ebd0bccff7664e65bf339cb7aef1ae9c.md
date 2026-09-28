### Title
Permissionless `flash_loan` drains any receiver contract's standing token allowance to the pool as fees - (File: contracts/pool/src/ops/flash.rs)

### Summary
`XoxnoLending` pool's flash-loan repayment is pulled via `transfer_from(pool, receiver, pool, amount + fee)`, where the spender is the pool contract itself. Because `flash_loan` is a permissionless entrypoint and the `receiver` argument is attacker-chosen, anyone can force a third-party contract that has granted a standing token allowance to the pool (the natural "approve once, repay later" flash-receiver integration pattern, exactly analogous to a Pearlmit approval to `TapToken`) into a flash loan it never requested. Each forced call consumes `amount + fee` of the victim's allowance: the principal is round-tripped but the `fee` is permanently booked as protocol revenue, so the victim's allowance is drained one fee at a time into supplier pockets.

### Finding Description
In `collect_repayment` the pool verifies only `asset.allowance(receiver, pool) >= total_repayment` and then calls `asset.transfer_from(pool, receiver, pool, &terms.total_repayment)` — the spender is the pool itself (satisfied by invoker contract auth), not the initiator. `apply` enforces only that `receiver` is a WASM contract (`require_wasm_receiver`) and that the market `is_flashloanable` with sufficient reserves; it never requires `initiator.require_auth()` and never checks that the receiver consented to this particular loan. The fee is credited to protocol revenue via `interest::add_protocol_revenue` and `credit_cash` in `finalize`/`book_fee`. Therefore an attacker submits `flash_loan(initiator = attacker, receiver = victim_contract, amount, data)`, the victim's `execute_flash_loan` callback runs (a receiver designed to repay via allowance typically does nothing or repays by approving), the allowance check passes on the victim's pre-existing approval, and the pool sweeps `amount + fee` from the victim.

### Impact Explanation
Theft of user/integrator funds: each invocation permanently transfers `fee = amount * flashloan_fee_bps / 10_000` out of the victim contract's balance into protocol revenue, distributed to suppliers. The attacker can repeat the call — or pick `amount` up to `min(allowance, reserves)` — until the victim's allowance (and balance) allocated for its own flash-repayment flow is consumed as fees. Revenue accrues to all suppliers including the attacker, and the principal leg also forces the victim to custody and return funds it never asked for. This mirrors M-04: a standing approval to the protocol contract is spent by an unrelated party because the spender in `transfer_from` is the contract itself, not the actual initiator.

### Likelihood Explanation
Likelihood is moderate, matching the medium severity of the analog. It requires (a) a market with `is_flashloanable` set and a nonzero `flashloan_fee`, and (b) a third-party contract that keeps a live `allowance(victim → pool)` — precisely the integration pattern `collect_repayment` was built for, since repayment by allowance implies receivers approve the pool ahead of time. Both conditions are plausible on any flash-loan-enabled market; no privileged access, timing, or oracle manipulation is needed, and the attack is a single unprivileged `flash_loan` call repeatable at will.

### Recommendation
Have the receiver return funds with an explicit `transfer` inside its `execute_flash_loan` callback (measured by the existing `require_balance` post-check) instead of pulling via `transfer_from`, or require `initiator.require_auth()` and pass the initiator's authorization into the repayment. If allowance-based pull is retained, the callback contract must at minimum authenticate `initiator`; preferably remove the `transfer_from` fallback entirely, mirroring the recommendation in M-04 not to fall back to a third-party allowance.

### Proof of Concept
```rust
// contracts/pool/tests/flows.rs-style scenario against the live entrypoint
// Precondition: `victim_receiver` (a WASM contract implementing
// execute_flash_loan) previously ran
//   token.approve(victim_receiver, pool, LARGE, expiry)
// as part of its repay-by-allowance integration.

let attacker = Address::generate(&env);
let pool     = /* pool address */;
let victim   = /* deployed receiver contract address */;
let asset    = /* flashloanable hub asset token */;

let fee_bps = /* market flashloan_fee */;
let amount: i128 = 1_000_000;
let expected_fee = amount * fee_bps as i128 / 10_000;

let victim_before = token::Client::new(&env, &asset).balance(&victim);

// Attacker never authorized anything; receiver is arbitrary.
client.flash_loan(&attacker, &victim, &asset, &amount, &Bytes::new(&env));

let victim_after = token::Client::new(&env, &asset).balance(&victim);
// Principal round-tripped, but the fee was pulled from the victim's
// standing allowance and booked as protocol revenue.
assert_eq!(victim_before - victim_after, expected_fee);
// Repeat until allowance(victim -> pool) is exhausted.
```

Key code path: `contracts/pool/src/ops/flash.rs` — `apply` pays out and invokes the attacker-chosen `receiver` (lines 40–71), and `collect_repayment` spends `allowance(receiver, pool)` via `transfer_from(pool, receiver, pool, total_repayment)` with the pool as spender (lines 165–180), with the fee booked into revenue in `book_fee`/`finalize` (lines 124–136). The absence of any initiator or receiver consent check in `apply` is the root cause.