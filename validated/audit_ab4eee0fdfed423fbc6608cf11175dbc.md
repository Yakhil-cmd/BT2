### Title
Tokens transferred directly to the pool or controller are permanently locked — no credit, refund, or sweep path exists - (File: contracts/pool/src/lib.rs)

### Summary

The Soroban analog of the `payable batch` locking bug: Soroban has no `msg.value`, but any token holder can call `token.transfer(pool_or_controller, amount)` directly. Both contracts custody real token balances while keeping separate `cash` bookkeeping. No entrypoint in either contract can ever return an unbooked balance — the pool's outbound transfers are all driven by the `cash` ledger, and the controller's refund paths only cover positive balance deltas measured inside a single call. Directly transferred tokens are stranded forever, matching the original report's "locked forever" impact.

### Finding Description

The pool's entire external surface is `create_market`, `update_params`, `upgrade`, `supply`, `borrow`, `withdraw`, `repay`, `update_indexes`, `recapitalize`, `flash_loan`, `create_strategy`, `seize_positions`, `net_settle`, `claim_revenue`, plus views — all mutators are `#[only_owner]` (the controller). There is no `sweep`/`skim`/`recover` entrypoint. Cash is explicitly an accounting book separate from the token balance (`contracts/pool/src/lib.rs` — "Cash is an accounting book, separate from the token balance").

Every outbound leg is bounded by bookkeeping, not by the real balance:

- `withdraw` / `borrow` transfer out amounts derived from `cash`.
- `repay` and `recapitalize` refund only the overpayment within that same call (controller pre-transfers the tokens, then the pool refunds the excess — the refund comes from the just-received amount).
- `claim_revenue` pays `min(cash, revenue)` — it cannot touch the unbooked surplus.

The threat model acknowledges this shape: "One token listed in several hubs shares physical pool custody even though market books are separate. Direct donations do not rewrite those books" (`docs/explanation/threat-model.md`), and "the adapter has no recovery path for arbitrary stranded assets". The same applies to the controller: `flash_position` refunds cover "only positive callback balance changes", and "undeclared controller balances are not credited" — a pre-existing controller balance is invisible to every flow.

So a direct `transfer` to either address permanently freezes the tokens: they inflate `token.balance(pool)` above `cash`, no code path ever transfers the difference out, and there is no admin/governance rescue function on the pool at all.

### Impact Explanation

Permanent freezing of funds: any user who mistakenly (or via a buggy integrator) sends tokens to the pool or controller address loses them irrevocably. The funds are not stealable either — they are simply unrecoverable, exactly the impact class of the source report ("any ethers sent are locked in the contract forever"). An additional protocol-level side effect exists — a donation makes `balance > cash` and trips the strict-equality checks in `flash_loan` — but that is a fail-closed liveness symptom, not the core impact, which is the irreversible loss of the transferred principal.

### Likelihood Explanation

Reachable by any unprivileged address: `token.transfer(my_address → pool, amount)` requires no protocol entrypoint. Likelihood is driven by user/integrator error rather than an exploit; integrators composing with the controller must authorize exact nested transfers (per `composing.md`'s token-pull ordering table, e.g. `self -> pool` for `supply`/`repay`), and a wrapper that sends to the wrong address or sends ahead of the call strands the funds. Medium likelihood of occurrence at scale, but each incident is bounded to the sender's own mistaken amount — hence Medium, matching the source severity.

### Recommendation

Add a recovery path for unbooked balances, mirroring the fix for the original report ("remove `payable`") adapted to Soroban:

- Add an owner-only `sweep(hub_asset, to)` on the pool that transfers `token.balance(pool) - sum_of_cash_backed_liabilities` (or simply `balance - cash` per market) to a governance-controlled address, so accidental donations are recoverable; and/or
- Document and enforce on integrators that tokens must only move via the authorized nested-transfer paths, and have the SDK/frontend refuse raw `transfer` operations targeting pool/controller addresses.

Alternatively, treat surplus `balance - cash` as protocol revenue in `claim_revenue`, which at minimum prevents permanent lockup.

### Proof of Concept

1. Deploy controller + pool with a listed market (e.g., USDC); a supplier deposits so `cash > 0`.
2. Any user calls `usdc.transfer(user, pool_address, 1_000e7)` directly on the token contract — this always succeeds; no contract logic can intercept it.
3. Observe `token.balance(pool) == cash + 1_000e7`, `get_reserves` still reports `cash`.
4. Attempt recovery: `withdraw`/`borrow`/`claim_revenue`/`recapitalize` all cap outflows at bookkeeping values; the surplus `1_000e7` has no exit path. No pool entrypoint exists that can move it (see the full surface in `contracts/pool/src/lib.rs:99-252`).
5. Same for the controller address: a direct transfer sits outside every balance-delta measurement (`payments::transfer_amount_measured` in `common/src/token.rs` only credits the current call's delta; `flash_position` refunds listed positive deltas only), so those tokens are equally stranded.