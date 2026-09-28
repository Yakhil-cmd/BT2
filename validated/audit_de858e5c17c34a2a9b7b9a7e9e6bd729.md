### Title
Permissionless `flash_loan` lets any caller spend a third-party contract's outstanding pool allowance and force it through an attacker-controlled callback - ([File: contracts/pool/src/ops/flash.rs])

### Summary
The pool's flash-loan settlement pulls repayment with `token.transfer_from(pool, receiver, pool, total_repayment)`, i.e. the pool is the pre-authorized `spender` and `receiver` is the allowance owner — the same AllowanceTarget shape as the reference incident. The only authorization required is on `initiator`; the `receiver` contract that owns the allowance is never asked to authorize the loan. Any unprivileged address can therefore nominate any WASM contract as `receiver`, fire its `execute_flash_loan` callback with attacker-chosen `initiator`/`data`, and consume that contract's `allowance(receiver, pool)` to pay the flash fee — repeatable until the allowance is exhausted.

### Finding Description
`Controller::flash_loan` routes to `process_flash_loan`, which calls `require_authorized_caller(env, caller)` and `require_wasm_receiver(env, receiver)` — the caller authorizes, the receiver only has to be a contract (`contracts/controller/src/strategies/flash_loan.rs`).

In the pool, `apply` transfers `amount` to `receiver`, invokes `receiver.execute_flash_loan(initiator, asset, amount, fee, pool, data)` with fully attacker-controlled `initiator` and `data`, then calls `collect_repayment` (`contracts/pool/src/ops/flash.rs:60-67`). `collect_repayment` merely asserts `asset.allowance(receiver, pool) >= total_repayment` and then performs `asset.transfer_from(pool, receiver, pool, total_repayment)` (`contracts/pool/src/ops/flash.rs:173-178`).

Root cause: there is no `receiver.require_auth()` and no check that `initiator == receiver` or that the receiver consented to this specific loan. The pool is a standing authorized spender of any contract that ever approved it, exactly like the AllowanceTarget in the incident — an attacker drives the "already-authorized spending path" (`flash_loan` → `transfer_from`) without the allowance owner's signature.

### Impact Explanation
Theft of user funds. For each invocation the victim contract nets `-fee` tokens: it receives `amount` and is debited `amount + fee` from its own balance via its allowance. An attacker can loop `flash_loan` with minimal `amount` until the victim's entire outstanding `allowance(victim, pool)` is burned as flash fees booked into protocol revenue (`book_fee` → `interest::add_protocol_revenue`). Additionally, the attacker-controlled `initiator` and `data` arguments are delivered to the victim's `execute_flash_loan` implementation — any receiver that acts on callback parameters (e.g., executes a stored or decoded plan, like the test receiver's `decode_request`/`reenter_*` modes in `mock/flash-loan-receiver/src/lib.rs`) can be driven into unintended behavior inside its own auth context.

### Likelihood Explanation
The attack is fully permissionless (`flash_loan` is an unprivileged entrypoint) and costs only transaction fees. It requires a victim contract with (a) an unexpired `allowance(victim, pool)` and (b) an `execute_flash_loan` entrypoint that doesn't reject a foreign initiator. SEP-41 allowances carry ledger expirations and honest receivers approve exactly `amount + fee` inside the callback (consumed by the pull), so standing residual allowance depends on integrations that pre-approve the pool or over-approve (the mock's `OverRepay` mode approves `total + 1`, which would remain spendable). Where such allowance exists, the drain is deterministic and repeatable. Severity: Medium.

### Recommendation
Bind the loan to the allowance owner: require `initiator == receiver` at the controller or pool level, or add `receiver.require_auth()` inside `flash::apply` before payout. Alternatively, have `collect_repayment` measure the receiver's balance delta rather than relying on a pre-existing standing allowance pattern that any third party can trigger.

### Proof of Concept
1. Victim contract `V` implements `execute_flash_loan` and holds `allowance(V, POOL) = A` with unexpired expiration (e.g., leftover from a prior over-approval).
2. Attacker calls `controller.flash_loan(attacker, hub_asset, amount, V, data)` for a flashloanable market, choosing `amount` so `amount + fee ≤ min(A, V's balance)`.
3. `process_flash_loan` authorizes only `attacker`; `require_wasm_receiver(V)` passes. Pool transfers `amount` to `V`, calls `V.execute_flash_loan(attacker, asset, amount, fee, POOL, data)`.
4. `collect_repayment` asserts `allowance(V, POOL) >= amount + fee` — true — then `transfer_from(POOL, V, POOL, amount + fee)` succeeds.
5. Net effect: `V` loses `fee`, the allowance decreases by `amount + fee`, fee accrues to protocol revenue. Repeat until `A` (and `V`'s balance) is exhausted. No signature from `V` is ever required.