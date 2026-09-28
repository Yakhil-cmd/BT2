### Title
`flash_loan` lets anyone pick an arbitrary `receiver` whose standing token allowance to the pool is drained via `transfer_from` — ([File: contracts/pool/src/ops/flash.rs])

### Summary
The pool's flash-loan repayment path calls `asset.transfer_from(pool, receiver, pool, total_repayment)` with a `receiver` address supplied by the untrusted `initiator`. Because the spender is the pool contract itself, the only thing standing between an attacker and a victim contract's tokens is a pre-existing `allowance(victim, pool)`. Anyone can permissionlessly trigger `controller::flash_loan` naming any WASM contract as `receiver`, causing the pool to pull `principal + fee` from a third party that merely holds an allowance to the pool.

### Finding Description
In `contracts/pool/src/ops/flash.rs`, `apply` pays `amount` to a caller-chosen `receiver`, invokes `execute_flash_loan` on it, and then calls `collect_repayment`, which does: [1](#0-0) 

`receiver` is an arbitrary argument threaded through `apply(env, hub_asset, initiator, receiver, amount, data)` [2](#0-1) , gated only by `require_wasm_receiver` (must be a contract) [3](#0-2) . `initiator` requires no relationship to `receiver`, and `flash_loan` is permissionless per `scripts/permissionless_entrypoints.txt` [4](#0-3) .

This is the Soroban analog of `safeTransferFrom(arbitrarySender, …)`: the `from` leg of the pull is attacker-controlled. The SEP-41 `transfer_from` authenticates the *spender* (the pool, which self-authorizes as invoker), never the `from` — so a victim contract that has ever approved the pool (the normal repayment mechanism for its own flash loans, or a leaked/residual allowance) can be debited without any authorization from the victim itself, provided its `execute_flash_loan` entrypoint does not revert on a call it didn't initiate.

### Impact Explanation
Theft of user funds. For a victim contract holding `allowance(victim, pool) >= amount + fee`, the attacker calls `flash_loan` with `receiver = victim`. The victim is credited `amount` principal and immediately debited `amount + fee`, so the net theft is the flash fee per call — but the attacker can also choose the victim's own pending repayment window: if a legitimate flash borrower has approved the pool but not yet been charged, an attacker can front-run by triggering `flash_loan(receiver = borrower)` to consume the allowance prematurely, or repeatedly extract the fee differential against any standing allowance. Stolen `fee` is booked as protocol revenue (`book_fee`), so the drain is laundered into the pool's own accounting.

### Likelihood Explanation
Medium. Exploitation needs a contract that (a) holds a non-zero allowance to the pool and (b) exposes a non-reverting `execute_flash_loan`. Condition (a) is the designed repayment flow — every flash borrower must approve the pool, and approval race windows or over-sized standing allowances are common integration patterns. The victim need not cooperate: `execute_flash_loan` receives only `(initiator, asset, amount, fee, pool, data)` and a receiver that doesn't validate `initiator` (e.g., one that just returns, or treats unexpected calls benignly) satisfies (b). The attack costs the attacker nothing — no capital, since the victim supplies the principal pull.

### Recommendation
Bind the repayment source to the entity that requested the loan and authenticated it:
- Require `initiator == receiver`, or require `initiator.require_auth()` in the controller entrypoint *and* treat `receiver` as untrusted: after the callback, pull repayment only up to what the receiver itself re-authorized within this call (e.g., snapshot `allowance(receiver, pool)` at entry in `prepare` and only allow collecting against allowance that did not pre-exist, or require the receiver to `transfer` rather than relying on `transfer_from`).
- Alternatively, measure the receiver's balance delta: require `balance(receiver)` to have returned the principal voluntarily, and only use `transfer_from` for the `fee` against a receiver the initiator authenticated.

### Proof of Concept
1. Victim contract `V` integrates flash loans and leaves `token.allowance(V, pool) = 1_000_000` (or holds a transient approval during its own loan).
2. Attacker calls `controller.flash_loan(initiator = attacker, receiver = V, amount = A, …)` with `A + fee <= allowance(V, pool)` and `A <= pool cash`.
3. Pool `transfer`s `A` to `V`, invokes `V.execute_flash_loan(attacker, asset, A, fee, pool, data)`; `V`'s implementation does not validate `initiator` and returns normally.
4. `collect_repayment` asserts `allowance(V, pool) >= A + fee` and executes `transfer_from(pool, V, pool, A + fee)` — authorized by the pool's invoker auth, never by `V` [5](#0-4) .
5. Net effect: `V` loses `fee` (or its pending repayment is consumed by a loan it never requested, breaking its own accounting), while the fee is booked as protocol revenue [6](#0-5) . Repeatable per call while allowance remains.

### Citations

**File:** contracts/pool/src/ops/flash.rs (L40-47)
```rust
pub(crate) fn apply(
    env: &Env,
    hub_asset: HubAssetKey,
    initiator: Address,
    receiver: Address,
    amount: i128,
    data: Bytes,
) -> i128 {
```

**File:** contracts/pool/src/ops/flash.rs (L48-49)
```rust
    let mut cache = prepare(env, hub_asset, amount);
    require_wasm_receiver(env, &receiver);
```

**File:** contracts/pool/src/ops/flash.rs (L123-128)
```rust
/// Credits cash and mints protocol revenue for the flash-loan fee.
pub(crate) fn book_fee(cache: &mut Cache, fee: i128) {
    let protocol_fee = Ray::from_asset(cache.env(), fee, cache.params().asset_decimals);
    interest::add_protocol_revenue(cache, protocol_fee);
    cache.credit_cash(fee);
}
```

**File:** contracts/pool/src/ops/flash.rs (L166-179)
```rust
fn collect_repayment(
    env: &Env,
    asset: &token::Client,
    pool: &Address,
    receiver: &Address,
    terms: &FlashTerms,
) {
    assert_with_error!(
        env,
        asset.allowance(receiver, pool) >= terms.total_repayment,
        FlashLoanError::InvalidFlashloanRepay
    );
    asset.transfer_from(pool, receiver, pool, &terms.total_repayment);
    require_balance(env, asset, pool, terms.balance_after_repayment);
```

**File:** scripts/permissionless_entrypoints.txt (L77-77)
```text
controller::flash_loan | caller-auth | INV-AUTH-03, INV-FLASH-01, INV-FLASH-02 | Anyone may borrow within a single call; the pool verifies principal plus fee is back before returning, and the flash-loan flag blocks monetary reentrancy into position flows.
```
