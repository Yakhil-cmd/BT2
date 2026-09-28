### Title
Unaccounted surplus tokens sent directly to a liquidity pool are permanently locked - (File: contracts/pool/src/lib.rs)

### Summary
The liquidity pool's `cash` book is the sole accounting source for every outflow path, and neither the pool nor the controller exposes any skim, sweep, or surplus-recovery entrypoint. Tokens transferred directly to the pool address (donations, airdrops, or rewards from rebasing-style mechanics) raise the SAC balance above the `cash` book and can never be withdrawn by anyone.

### Finding Description
`LiquidityPool` keeps a static accounting book: `cash`, `supplied`, `borrowed`, `revenue` and supply/borrow indexes. The contract's own docs state that "Cash is an accounting book, separate from the token balance" (contracts/pool/src/lib.rs:34-36). Every token outflow — `supply`/`withdraw` payouts, `borrow`, `flash_loan` settlement, `claim_revenue`, `recapitalize` refunds — is bounded by the book (`Cache::require_reserves` reads `cash`, not the live balance), and every inflow that moves the book is measured by the controller via balance-delta of the transfer it itself initiated (`markets::recapitalize` prefunds then credits only its measured receipt, contracts/controller/src/markets.rs:154-163).

A test pins the exact behavior: an unsolicited `token.transfer(payer → pool)` of `7 * UNIT` is acknowledged as "an unsolicited donation belongs to no market's cash book" — the pool balance becomes `state.cash + other.cash + 7 * UNIT` and stays there while books remain unchanged (tests/test-harness/tests/pool_money_flow_audit.rs:86-96). No entrypoint lets the surplus be claimed:

- `withdraw`/`borrow` are capped by `cash` and position shares; the surplus is invisible to them.
- `claim_revenue` pays out only scaled `revenue` shares.
- `recapitalize` applies only up to the backing shortfall and measures only the caller's own fresh transfer — pre-existing surplus is not capturable (contracts/controller/src/markets.rs:140-164; contracts/pool/tests/flows.rs:3328-3344 confirm the pool trusts only the owner's declared amount, and only up to the shortfall).
- There is no `sweep`/`recover`/`skim` function on the pool (contracts/pool/src/lib.rs:99-157 lists every entrypoint, all `#[only_owner]` mutators or views) or on the controller, which additionally rejects borrow/withdraw payouts addressed to the pool or itself (tests/test-harness/tests/controller/recipient_is_protocol_contract.rs:1-5).

Because `cash` is never reconciled to `balanceOf(pool)`, the surplus stays above the book forever: guards pass (the book is fully backed), but the extra tokens are unspendable by suppliers, borrowers, the protocol, or the sender.

### Impact Explanation
Permanent freezing of funds: any tokens that reach the pool outside a measured flow — accidental direct transfers, third-party rewards/airdrops to the pool or controller address — become irrecoverable. The sender cannot reclaim them, suppliers cannot withdraw them (their claims are limited to indexed shares), and the protocol has no recovery lever. This mirrors the source report: static `poolAmount`-style bookkeeping versus dynamic `balanceOf` leaves surplus value stranded in the custody contract.

### Likelihood Explanation
Medium. The trigger requires only an unprivileged direct token transfer to the pool/controller address — an explicitly in-scope action. Mistaken transfers to contract addresses are a recurring real-world pattern, and any rewards/airdrop mechanics targeting token holders would hit the pool. It is not an exploitable theft path (no attacker profits), which bounds severity, but the lockup is unconditional and permanent once it occurs.

### Recommendation
Add an owner-gated surplus-recovery path that pays `balanceOf(pool) - (sum of all markets' cash)` to a designated recipient, or have `recapitalize`/a dedicated entrypoint credit the pre-existing balance surplus up to the backing shortfall before requiring fresh funds. At minimum, document that the pool address must never receive tokens outside measured flows and consider routing such surplus into revenue shares so it remains claimable.

### Proof of Concept
The behavior is already pinned by the in-repo test `pool_all_money_paths_preserve_books_and_shared_token_custody` (tests/test-harness/tests/pool_money_flow_audit.rs:86-96): after `token.transfer(&payer, &market.pool, &(7 * UNIT))`, `token.balance(&market.pool) == cash_market1 + cash_market2 + 7 * UNIT` while every market book is unchanged — the `7 * UNIT` delta has no owner, no claim path, and no entrypoint that references it. A standalone reproduction: (1) supply 1_000 USDC, borrow against it; (2) directly `transfer` X tokens to the pool SAC address; (3) observe that `get_sync_data` is unchanged and no sequence of `withdraw`/`borrow`/`claim_revenue`/`recapitalize` calls can move the extra X — `withdraw` of all shares leaves `token.balance(pool) == X` at the end.