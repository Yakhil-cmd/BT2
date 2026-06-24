Audit Report

## Title
Non-Expiring ICRC-2 Approvals Bypass `prune()` Causing Unbounded `AllowanceTable` Growth — (`rs/ledger_suite/common/ledger_core/src/approvals.rs`)

## Summary
`AllowanceTable::prune()` exclusively iterates the `expiration_queue`. Non-expiring approvals (`expires_at = None`) are never inserted into `expiration_queue`, so `prune()` is a no-op when all approvals are non-expiring. The `allowances` BTreeMap has no size cap, allowing an unprivileged attacker to accumulate permanent heap entries until the ledger canister exhausts its memory and becomes unavailable.

## Finding Description
In `approve()`, `insert_expiry()` is called only inside `if let Some(expires_at) = expires_at` (lines 265–267). When `expires_at` is `None`, the allowance is written only to `allowances` and never to `expiration_queue`. In `prune()` (lines 373–399), the loop checks `first_expiry()` first; when the expiration queue is empty it hits the `None => { return pruned; }` branch at line 383–385 and returns 0 immediately. `apply_transaction` calls `prune(now, APPROVE_PRUNE_LIMIT)` at line 231 on every transaction, but this call is a no-op when all approvals are non-expiring. The `arrival_queue` field exists in `HeapAllowancesData` (line 74) and `clear_arrivals()` is defined in the trait (line 63), but no `insert_arrival` or `pop_first_arrival` method exists in the trait, and `approve()` never populates `arrival_queue` — indicating an incomplete pruning mechanism for non-expiring entries. There is no `max_allowances` cap enforced anywhere in the approve path. Each unique `(account, spender)` pair with a non-expiring approval occupies a permanent BTreeMap entry that is only removed by explicit revocation (`amount = 0`) or full consumption via `use_allowance`.

## Impact Explanation
This matches the allowed High impact: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS." The ICP and ICRC-1/2 ledger canisters are core financial infrastructure. Exhausting the ~4 GB IC heap via accumulated allowance entries causes allocation failures and canister traps, rendering the ledger unavailable. This is a state-exhaustion attack through legitimate protocol calls, not raw network flooding.

## Likelihood Explanation
Each approval requires a funded account paying the transaction fee (currently 10,000 e8s = 0.0001 ICP per transaction). At ~100–200 bytes per BTreeMap entry, exhausting 4 GB requires roughly 20–40 million entries, costing 2,000–4,000 ICP minimum. The `max_transactions_in_window` throttle limits rate but not total volume. A patient, well-funded attacker can accumulate entries over weeks or months. The ICP ledger is a high-value target, making this cost feasible for a motivated adversary.

## Recommendation
1. Enforce a maximum total allowance count: reject `icrc2_approve` when `len_allowances()` exceeds a configured cap (e.g., 10 million).
2. Complete the `arrival_queue` implementation: add `insert_arrival` / `pop_first_arrival` to the `AllowancesData` trait, populate it in `approve()` for non-expiring entries, and extend `prune()` to evict the oldest non-expiring approvals when the table exceeds a threshold.
3. Consider a higher fee or a held deposit for non-expiring approvals to raise the economic cost of accumulation.

## Proof of Concept
```rust
// Unit test against HeapAllowancesData
let mut table = AllowanceTable::<HeapAllowancesData<Account, Tokens>>::default();
let now = ts(1_000_000);

for i in 1u64..=10_000 {
    table.approve(&Account(i), &Account(i + 100_000), tokens(1_000_000), None, now, None).unwrap();
}
assert_eq!(table.len(), 10_000);

// Simulate 1000 apply_transaction calls each invoking prune(now, 100)
for _ in 0..1000 {
    let pruned = table.prune(now, 100);
    assert_eq!(pruned, 0); // no-op: expiration_queue is empty
}

// Table size unchanged — non-expiring approvals accumulate permanently
assert_eq!(table.len(), 10_000);
```
This test is directly runnable against `rs/ledger_suite/common/ledger_core/src/approvals/tests.rs` using the existing `HeapAllowancesData` and `AllowanceTable` types.