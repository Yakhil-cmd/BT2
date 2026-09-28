### Title
Tokens transferred directly to the pool or controller are permanently locked — no rescue path exists for unbooked balances - ([File: contracts/pool/src/lib.rs])

### Summary
The H01 class (arbitrary-token deposits trapped because the contract can only operate on one fixed token implementation) maps onto XOXNO Lending as follows: every outbound token transfer from `Pool` and `Controller` is bound to a listed `HubAssetKey` market's `asset_id`, and neither contract exposes a `sweep`/`rescue`/arbitrary-withdraw entrypoint. A direct `token.transfer` to either contract of an unlisted token — or of a listed token outside the credited books — becomes permanently unrecoverable. The pool's own tests pin this: an unsolicited donation "belongs to no market's cash book" and simply inflates physical custody.

### Finding Description
Soroban has no ABI-mismatch problem — `token::Client` in `common/src/token.rs` is already a uniform interface — so the interface-mismatch half of H01 does not exist. The stuck-funds half does:

- `Pool` outbound transfers occur only through market operations (`withdraw`, `borrow`, `repay` refund, `recapitalize`, `flash`) that all resolve `HubAssetKey` → `Params.asset_id`. `contracts/pool/tests/flows.rs` proves the key and `asset_id` are structurally identical, so no payload can name a token that is not its own market's asset.
- `Controller` outbound transfers are similarly confined to market assets (`payments.rs`, `strategies/legs.rs`, `markets.rs::recapitalize`). Flash-position refunds cover only positive callback deltas of tokens the caller declared in `refund_assets`; per `skills/xoxno-lending-contracts/flash-loans.md`, "an undeclared token left on the controller is neither deposited nor refunded," and "neither category sweeps prior balances."
- Neither `contracts/pool/src/lib.rs` nor `contracts/controller/src/lib.rs` exposes any sweep/rescue entrypoint (contrast `contracts/swap-aggregator/src/lib.rs::sweep_balance`, which exists precisely because stray balances otherwise have no exit).

### Impact Explanation
Any user who sends an unlisted token to the `Pool` or `Controller` address loses it permanently — there is no code path, privileged or not, that can transfer it out. For a listed token, a direct donation is likewise unrecoverable by the sender: it joins physical custody above the sum of all markets' cash books and can never be withdrawn, repaid, or claimed as revenue, since all claims are denominated in scaled shares of the books, not custody. This is permanent freezing of user funds, matching H01's accepted impact.

### Likelihood Explanation
Reachable by any unprivileged address via a plain `token.transfer` — exactly the "direct token transfers to the pool or controller" path listed in scope. It requires user error (sending to the contract address directly, or pushing an undeclared/wrong asset inside a `flash_position` callback — the integration test `fp_plan_wrong_asset` demonstrates a wrong-asset push leaves the token on the controller uncredited), which lowers likelihood; the loss is then unconditional.

### Recommendation
Add a governance-gated (timelock `execute`) rescue entrypoint on both `Pool` and `Controller` that transfers out (a) any token address for which no market exists in any hub, and (b) for listed tokens, only `balance - Σ cash(book) - reserved` surplus — i.e., the same reserve-aware pattern as `swap-aggregator`'s `sweep_balance` (`balance - reserved_fee_balance`). Without it, unbooked balances are permanently bricked.

### Proof of Concept
1. Deploy pool/controller; list a USDC market in hub 1.
2. Alice calls `token::Client::new(env, &unregistered_token).transfer(&alice, &pool_addr, &amount)` — or, for the controller path, a `flash_position` receiver pushes an asset not declared in `collaterals`/`refund_assets`.
3. Enumerate every public entrypoint on `Pool` (`supply`/`withdraw`/`borrow`/`repay`/`liquidate` legs/`recapitalize`/`claim_revenue`/`flash_loan`) and on `Controller`: all require a `HubAssetKey` resolving to a `Params` whose `asset_id` equals the token (`contracts/pool/tests/flows.rs:3519-3575` pins this structural identity). The unlisted token resolves to `PoolNotInitialized`; listed-token donations are excluded from every cash book (`pool_money_flow_audit.rs:86-96`).
4. `token.balance(&pool_addr)` retains the full amount with no reachable transfer-out — funds permanently frozen.

Severity: Medium (permanent loss, conditional on user error).