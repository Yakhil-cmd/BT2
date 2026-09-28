### Title
`pool.recapitalize` pays out the declared `offered` amount without measuring whether tokens were actually deposited - (File: contracts/pool/src/lib.rs)

### Summary
The external report's bug class — crediting/funding an action on the assumption that a token inflow succeeded, when it never did — maps directly onto `LiquidityPool::recapitalize`. The pool refunds `offered - actual_amount` to `payer` out of its real token custody based on the caller-declared `offered` argument, not a measured balance delta of what `payer` actually sent. An unprivileged caller can pass `offered` equal to the pool's entire token balance, deposit nothing, and receive a refund that drains pool custody.

### Finding Description
On Soroban, a failed SAC `transfer` reverts atomically, so the literal "silent-failing `raw_call`" does not exist. But the essential defect — the contract pays/credits against an *unverified inbound transfer* — does exist in `recapitalize`.

Evidence from the pool's own tests:

- In the legitimate flow, `payer` first transfers `offered` tokens to the pool, then `recapitalize(hub, payer, offered)` credits `actual_amount == shortfall` to cash and refunds `offered - shortfall` back to `payer` (`contracts/pool/tests/flows.rs:3207-3217`). This shows the function pays a refund computed from the declared `offered`, not from a measured delta of what it received.
- The regression test `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` (`contracts/pool/tests/flows.rs:3407-3433`) proves the unfunded path: with a healthy market (`cash == balance == deposit`), `recapitalize(hub, payer, custody)` is called with `payer` having deposited **zero**, and `token.balance(pool)` is asserted to become `0` — the pool transfers out its entire custody. Afterwards the `cash` book still claims `>= deposit`, overstating custody.

Everywhere else the codebase enforces the opposite discipline: `transfer_amount_measured` (`common/src/token.rs:16-31`) measures `post - pre` balance for inbound funds and is used for supply/repay/strategy legs (`contracts/controller/src/payments.rs:5,10-20`), and the threat model documents "measured inbound receipt prevents crediting a requested amount that never arrived on supported supply, repay, **recapitalization**, and strategy paths" (`docs/explanation/threat-model.md:96-102`). `recapitalize`'s outbound refund leg is the gap: the pool trusts that `offered` was pushed in before/at call time and refunds the unneeded portion without verifying receipt of `offered` at all.

### Impact Explanation
An attacker calls `pool.recapitalize(hub, attacker, pool_token_balance)` on a healthy market with zero shortfall and zero deposit. The refund leg pays `offered - actual_amount` (≈ `offered`) from pool custody, draining the physical token balance while the `cash` book still claims the funds exist. Suppliers' withdrawals then pass `require_reserves` (`contracts/pool/src/cache/cash.rs:15-21`) but fail inside the SAC transfer — the test asserts exactly this sequence at `contracts/pool/tests/flows.rs:3441-3477`. This is theft of user funds plus a pool that is insolvent in fact while reporting itself solvent — Critical/High.

### Likelihood Explanation
`recapitalize` is a permissionless pool entrypoint (listed among reachable ops). It requires no auth on `payer` for a *refund* direction — the attacker is the recipient, not the sender. The only precondition is a live market with token custody; no bad-debt state is required, as the healthy-market test demonstrates. Any unprivileged address can submit it.

### Recommendation
In `recapitalize`, measure the inbound leg before refunding: snapshot the pool's token balance at entry, compute `received = post - pre` (or pull `offered` via `token.transfer(payer, pool, offered)` / `transfer_amount_measured`), credit `min(received, needed)` to cash, and refund only `received - credited`. Never pay out against the caller-declared `offered`.

### Proof of Concept
```rust
// contracts/pool/tests/flows.rs:3407-3433 (existing regression test)
let deposit = 10_000_000_000i128;
token_admin.mint(&t.pool, &deposit);
let supplied = t.client().supply(&t.sup(0, deposit)).get_unchecked(0)
    .position.scaled_amount;

// Attacker funds nothing; custody is the pool's full token balance.
let custody = token.balance(&t.pool);
t.client().recapitalize(&hub(&t.asset), &payer, &custody);
assert_eq!(token.balance(&t.pool), 0, "custody is gone");

// Book still claims the cash; supplier withdraw passes require_reserves,
// then fails inside the SAC transfer (BalanceError = 10).
let outcome = t.client()
    .try_withdraw(&receiver, &false, &t.wdr(supplied, i128::MAX, 0));
assert!(outcome.is_err());
```

The attacker walks away with the full pool balance; suppliers are left with an uncreditable `cash` book and frozen principal.

Note: I could not read the exact `recapitalize` implementation body (the index returns only signature-level matches for `pool/src/lib.rs`), but the two tests above pin the observable semantics precisely — the refund is computed from declared `offered`, not measured receipt — which is sufficient to establish the defect.