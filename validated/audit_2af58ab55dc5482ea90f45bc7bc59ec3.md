### Title
Tokens transferred directly to the Liquidity Pool are permanently locked — no rescue path exists (File: contracts/pool/src/lib.rs)

### Summary

The Liquidity Pool keeps `cash` as a pure accounting book that is deliberately decoupled from the contract's actual token balance (`lib.rs:34-36`: "Cash is an accounting book, separate from the token balance"). Tokens can only enter the book via `supply`/`recapitalize`/`repay` flows orchestrated by the controller, which transfers tokens in *before* the pool credits anything. Consequently, any tokens pushed to the pool address via a bare `token.transfer` — a donation, a mistaken user transfer, or dust swept by an integrator — raise the token balance but are never credited to cash, shares, or revenue. The pool exposes no `sweep`, `rescue`, or skim-style entrypoint, so the surplus is unrecoverable by any caller, privileged or not.

### Finding Description

The external report flagged `QVBaseStrategy` for missing a `withdraw` to rescue stuck funds. The XOXNO pool has the same shape, and is worse in one respect: the mistaken sender cannot even self-recover, because every outbound leg is bound by the internal cash book, not the token balance:

- `withdraw` burns supply shares and pays out bounded by cash (`lib.rs:154-163`); a donor holds no shares.
- `claim_revenue` pays `min(cash, revenue)` (`lib.rs:243-252`) — cash-bounded, so donated balance is unreachable.
- `recapitalize` credits only `min(amount, backing_shortfall)` and transfers the excess back to the payer (`ops/recapitalize.rs:52-58`, refund at `:34`). It requires the controller to push tokens in first and never absorbs pre-existing balance surplus — a donation does not even count toward the backing shortfall, since the shortfall is computed on the cash book, not `token.balance(pool)`.
- `flash_loan` checks balance around payout/callback/repayment but only enforces solvency of the book; it cannot disburse stray balance.
- The `LiquidityPoolInterface` (`lib.rs:100-325`) contains no sweep/rescue/stale-balance entrypoint at all — every mutator is `#[only_owner]` (the controller), and none transfers out tokens beyond booked obligations.

The swap-aggregator contract in the same repo demonstrates the missing pattern: its `sweep_balance` sends the owner `balance - ReservedTotal`, i.e., exactly the stray-balance-above-backing recovery the pool lacks (`contracts/swap-aggregator/src/lib.rs:189-202`). No equivalent exists on the pool or controller side, and the controller's own outbound legs are all balance-delta-measured against booked obligations.

### Impact Explanation

Permanent freezing of funds. Any non-booked token balance on the pool — direct transfers, airdrops to the contract address, fee-on-transfer artifacts, tokens pushed by a compromised or buggy integrating contract — is locked forever. Unlike the Allo analog where the pool admin could at least in principle upgrade, the only outbound paths here are cash-book-bound, so even a cooperative governance/admin cannot route the surplus out through a legitimate entrypoint (the only remaining lever is a WASM `upgrade`, outside the in-scope surface).

### Likelihood Explanation

Low-to-moderate frequency, medium impact per event, matching the original Medium rating. Mistaken direct transfers to well-known contract addresses are a recurring real-world occurrence; hub/spoke markets over one physical pool balance (`lib.rs` accounting model) mean a single pool address accumulates exposure across all listed assets. It requires a user or integrator error rather than an adversarial action, but the loss is unrecoverable by design once it happens.

### Recommendation

Add a rescue entrypoint to the pool mirroring the aggregator's design: an owner- or governance-gated `sweep(token, recipient)` that transfers `token.balance(pool) - Σ booked obligations` (cash plus any reserved amounts), so stray balances are recoverable while every market's cash book stays fully backed. Alternatively, document and enforce via `guards::backing_shortfall` a path where excess physical balance can be credited to cash/revenue (e.g., allow `recapitalize` to absorb pre-existing surplus instead of only payer-injected funds).

### Proof of Concept

1. Controller creates market `(hub_id, USDC)`; suppliers deposit; cash book = 1,000 USDC, pool token balance = 1,000 USDC.
2. Any unprivileged address calls `token::Client(USDC).transfer(sender, pool_addr, 500)` directly — explicitly permitted by the allowed "direct token transfers to the pool or controller" vector.
3. Pool balance is now 1,500 USDC; cash book unchanged at 1,000. `get_reserves` still reports 1,000.
4. Attempted recovery: `recapitalize(hub_asset, payer, amount)` refunds `amount - min(amount, shortfall)` to `payer` (`ops/recapitalize.rs:52-58`); with no backing shortfall it applies 0 and refunds everything — the 500 is never credited. `claim_revenue` is capped by cash. `withdraw` requires shares. No entrypoint on `LiquidityPoolInterface` moves the surplus.
5. The 500 USDC remains in the contract with no code path to disburse it — permanent freezing of funds.

Confidence note: I verified the pool interface has no sweep entrypoint and that `recapitalize` cannot absorb pre-existing balance surplus. I did not fully enumerate the governance op list (`contracts/governance/src/op.rs`) to confirm no privileged arbitrary-call op could already rescue such balances; if governance can execute arbitrary contract invocations as the pool owner, the loss would still require privileged intervention and does not change the unprivileged-facing defect, but it may affect severity assessment.