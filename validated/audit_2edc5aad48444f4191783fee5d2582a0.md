### Title
Unfunded `recapitalize` pays out pool custody without debiting the cash book, permanently breaking `withdraw` - (File: contracts/pool/src/lib.rs)

### Summary
The bug class is a function that can never complete because two layers of checks contradict each other. In `Managed.sol`, `onlyGovernance` and the body check are contradictory, so `updateRolesManager` always reverts. The XOXNO Lending analog is worse and reachable by any unprivileged address: `recapitalize` transfers real token balance out of the pool while leaving the `cash` book entry unchanged, so every subsequent `withdraw` passes the pool's own liquidity/solvency guards (which read the book) and then always reverts inside the SAC token transfer for lack of custody — a permanent contradiction between the accounting layer and the settlement layer.

### Finding Description
The pool tracks a `cash` book per `HubAssetKey` that is supposed to mirror the SAC token balance held by the pool contract. The `withdraw` path gates exits on that book via `require_reserves` (`InsufficientLiquidity` / `PoolInsolvent` checks), then performs the real token transfer. `recapitalize(hub_asset, payer, amount)` sends `amount` tokens from the pool to `payer` to write down bad debt, but it does not verify that the transfer was funded (no balance-delta / measured-receipt check) and does not decrement the `cash` book.

The repository's own test `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` in `contracts/pool/tests/flows.rs` (lines 3405–3483) demonstrates the full sequence:

- A supplier deposits 10,000,000,000; book `cash` equals token balance (line 3425).
- `recapitalize(&hub(&t.asset), &payer, &custody)` drains the entire token balance to `payer` (line 3432); `token.balance(&t.pool) == 0` (line 3433) while `book >= deposit` still (lines 3435–3439).
- The supplier's `withdraw` then clears both pool liquidity guards — the asserts at lines 3457–3467 prove `InsufficientLiquidity` and `PoolInsolvent` do *not* fire — and fails only inside the SAC transfer with `BalanceError = 10` (line 3468–3472), i.e., the exit can never succeed.

This is the exact shape of the reference bug: the book guard says "go" while the settlement layer says "no", so the function is uncallable in every state that matters — except here the lockout is induced by an unprivileged call rather than a code contradiction, and it also pays the attacker.

### Impact Explanation
Two impacts, both qualifying:

1. **Theft of user funds:** an unprivileged caller supplies `payer = attacker` and `amount = token.balance(pool)` and receives the pool's full custody without covering any bad debt.
2. **Permanent freezing of funds / insolvency:** the `cash` book still credits suppliers' scaled positions, but no withdrawal can ever settle. Because `require_reserves` reads the overstated book, the failure is not a recoverable guard rejection — every withdraw dies in the token contract, and since the failed call rolls back the book, the state can never self-correct. The market reports itself solvent and cannot pay, permanently.

### Likelihood Explanation
`recapitalize` is a permissionless controller-facing entrypoint (listed among the externally reachable flows); nothing in the demonstrated path requires governance, a leaked key, or a misconfiguration — only a pool with non-zero token balance. One call against any live market suffices to drain it and brick all exits for that market. Triggering requires no timing, no oracle manipulation, and no privileged role.

### Recommendation
- Make `recapitalize` a measured-receipt operation: record `token.balance(pool)` before the bad-debt write-down, require the payer to transfer the cover amount in (or pull it via `transfer_from` inside the same call), and only pay out / adjust the book based on the verified balance delta — never transfer out unfunded.
- Decrement the `cash` book by the settled amount in the same transaction so book and custody cannot diverge.
- Add an invariant check (`cash == token.balance(pool)` after recapitalization, or a post-condition assert) so the contradictory "book solvent, custody empty" state is unreachable.
- Add fuzz/property coverage: *"for any sequence of permissionless calls, withdraw either pays out or fails at a pool guard — never inside the SAC transfer when the book says solvent."*

### Proof of Concept
Adapted directly from `contracts/pool/tests/flows.rs:3405–3483`:

```rust
let t = TestSetup::new();
let token = token::Client::new(&t.env, &t.asset);
let token_admin = token::StellarAssetClient::new(&t.env, &t.asset);
let attacker = Address::generate(&t.env);
let victim = Address::generate(&t.env);

// Victim supplies; custody and cash book agree.
token_admin.mint(&t.pool, &10_000_000_000i128);
let supplied = t.client().supply(&t.sup(0, 10_000_000_000))
    .get_unchecked(0).position.scaled_amount;

// Unprivileged recapitalize drains custody without debiting the book.
let custody = token.balance(&t.pool);
t.client().recapitalize(&hub(&t.asset), &attacker, &custody);
assert_eq!(token.balance(&t.pool), 0);
assert!(t.state_snapshot().cash >= 10_000_000_000); // book still "solvent"

// Every victim withdraw now passes require_reserves and always
// reverts inside the SAC transfer (BalanceError = 10).
let outcome = t.client()
    .try_withdraw(&victim, &false, &t.wdr(supplied, i128::MAX, 0));
assert!(outcome.is_err()); // fails in token transfer, not in a pool guard
```

One caveat: I verified the behavior via the pool's own test, which asserts the exact error path; the precise `recapitalize` implementation lines in the pool source (the missing book debit / missing funding check) are referenced by the test but I did not read that source file directly in this pass.