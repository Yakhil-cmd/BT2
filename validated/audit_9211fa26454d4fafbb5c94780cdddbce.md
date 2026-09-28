### Title
Tokens airdropped or accidentally sent to the LiquidityPool are permanently locked — no sweep/recovery path exists - (File: contracts/pool/src/lib.rs)

### Summary
The `LiquidityPool` contract holds the physical token balances backing every market, but exposes only owner-gated accounting operations (supply, borrow, withdraw, repay, seize, flash, revenue). It has no entrypoint to recover tokens that arrive outside the accounting book — direct transfers, airdrops, or yield-farming rewards earned by the pool address. `cash` is an accounting book separate from the token balance, so stray tokens inflate the real balance without ever becoming withdrawable, and no unprivileged or privileged code path can move them out.

### Finding Description
The pool's interface enumerates every mutation: `create_market`, `update_params`, `upgrade`, `supply`, `borrow`, `withdraw`, `repay`, `update_indexes`, `recapitalize`, `flash_loan`, `create_strategy`, `seize_positions`, `net_settle`, and `claim_revenue` — all gated by `#[only_owner]` and all operating strictly on the accounting book (`cash`, scaled supply/debt shares, revenue) rather than the raw token balance (contracts/pool/src/lib.rs:99-252). The architecture note confirms the separation: "Cash is an accounting book, separate from the token balance" (contracts/pool/src/lib.rs:34-36).

Consequences of the missing sweep:

- **Market-asset donations**: `recapitalize` deliberately credits cash only up to `guards::backing_shortfall` and refunds the excess to `payer` (contracts/pool/src/lib.rs:183-194), so excess real balance over the book is never absorbed. Withdrawals debit `cash`, so suppliers cannot claim the surplus either — it is stranded.
- **Non-market tokens / airdrops**: Any ERC-20-equivalent (Soroban token) sent to the pool address, including airdrops earned because the pool holds an eligible asset, has zero recovery paths. `claim_revenue` only pays out accounted `revenue` shares capped by `cash` (contracts/pool/src/lib.rs:243-252).
- The governance `Recovery` mechanism is only a canceller-set reset for the timelock, not a token rescue (contracts/governance/src/timelock/recovery.rs:14-43).
- The only remaining escape is `upgrade` to new WASM — a privileged, out-of-band remedy identical to having no in-contract recovery at all.

### Impact Explanation
Permanent freezing of unclaimed yield and stray funds. Tokens airdropped to the pool (or controller) address — a realistic scenario since the pool is a large holder of airdrop-eligible assets — plus any accidental direct transfers, are locked forever with no recovery mechanism. This matches the accepted "theft or freezing of unclaimed yield / permanent freezing of funds" impact class. The flash-loan balance checks only verify principal+fee round-trip (contracts/pool/src/lib.rs:196-210) and cannot be abused to extract the excess, so the funds are frozen rather than stealable.

### Likelihood Explanation
Medium-low likelihood, medium impact. Soroban tokens can be sent to any address without opt-in, so accidental transfers accumulate over time, and protocols holding large token balances are periodic airdrop targets. Every market asset adds an address that may qualify for holder rewards. The loss is unbounded in value but requires an external crediting event to materialize.

### Recommendation
Add an owner-only `sweep(token: Address, to: Address, amount: i128)` entrypoint to `LiquidityPool` (and an equivalent on the controller). For tokens that back a live market, cap the sweepable amount at `token_balance - (cash + outstanding obligations)` so the sweep can never touch funds backing supplier claims; for non-market tokens, allow full recovery. Route the call through governance/timelock for transparency.

### Proof of Concept
1. Any user (or an airdrop contract) executes `token.transfer(pool_address, X)` for token T. If T is a market asset, `cash` and `total_supply` are unchanged, so `token_balance > cash` permanently. If T is not a market asset, it is entirely unaccounted.
2. Enumerate the pool interface: the only functions that move tokens out are `borrow` (mints debt against `cash`), `withdraw` (burns supply shares against `cash`), `claim_revenue` (burns accounted revenue shares), and `flash_loan` (requires full repayment + fee in the same tx). None reference the surplus `token_balance - accounted`.
3. Result: `X` units of T remain at the pool address with no reachable path — unprivileged or owner — that transfers them out, short of a privileged WASM `upgrade`.