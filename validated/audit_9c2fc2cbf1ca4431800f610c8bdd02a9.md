### Title
Tokens transferred directly to the Controller are permanently frozen — no recovery or sweep path exists - ([File: contracts/controller/src/payments.rs])

### Summary
The bug class is "value sent to a contract that can only handle a specific asset gets stuck because there is no withdrawal path." Soroban has no `msg.value`, but the direct analog exists: any unprivileged address can `token.transfer()` assets straight to the controller contract, and no controller, pool, or governance entrypoint can ever move the controller's pre-existing token balance. Every controller outflow is computed as a measured balance *delta* above a snapshot taken at entry (`refund_controller_balance_delta`), which by construction preserves whatever balance existed beforehand. Stray tokens are therefore permanently locked.

### Finding Description
The controller's only outbound-transfer helper for incidental balances is `refund_controller_balance_delta` in `contracts/controller/src/payments.rs`:

```rust
let controller = env.current_contract_address();
let excess = balance_delta_since(env, asset, &controller, balance_before);
if excess > 0 {
    token::Client::new(env, asset).transfer(&controller, refund_to, &excess);
}
```

This refunds only the increase since `balance_before`; the comment states "preserving the pre-existing balance." No other controller function — `supply`, `borrow`, `withdraw`, `repay`, `liquidate`, `flash_loan`, `flash_position`, `multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `migrate_from_blend`, `claim_revenue`, `recapitalize` — spends the controller's own standing balance; all payments are pulled from the caller via `require_auth` or routed through the pool. The controller also exposes no `sweep`/`rescue`/`recover` entrypoint (unlike `sweep_balance` on the swap-aggregator), and governance ops contain no arbitrary token-transfer operation that could free a controller-held balance.

Note the asymmetry on the pool side: stray tokens sent to the pool are *not* frozen — pool custody is fungible with the `cash` book, and `ops::repay`/`ops::recapitalize` refunds pay out of real custody (as `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` demonstrates). The controller, by contrast, is a dead end: every code path is engineered to leave its baseline balance untouched.

### Impact Explanation
Any token balance held by the controller contract — whether from a user mistakenly calling `token.transfer(controller, …)`, a dust refund routed to the wrong address, or a future callback sending to the controller — is permanently frozen. There is no admin, governance, or permissionless function that can extract it, matching the "contract has no function to pull out the sent asset" impact of the reference report.

### Likelihood Explanation
Reachable by any unprivileged address via a plain Soroban token `transfer` to the controller address. It requires a sender mistake (or an integration passing the controller as a recipient), so likelihood is low-to-moderate — the same self-inflicted-but-unrecoverable profile as the original Medium finding. Funds already held by the controller cannot be recovered by anyone.

### Recommendation
Add a controller-level recovery path for balances not owed to any caller — e.g., a governance-gated `sweep(token, recipient)` that transfers `balance - reserved` (the controller reserves nothing, so the full balance), or route such a sweep through a timelocked governance operation. Alternatively, if the design intends the controller to never hold tokens, document that and consider a refund leg that sends the *full* measured balance when the pre-existing balance was a donation.

### Proof of Concept
1. User calls `token::Client::transfer(user → controller, amount)` on any supported asset (e.g., XLM SAC).
2. Enumerate every controller entrypoint: all outbound transfers either go pool→user (`withdraw`, `borrow`, `claim_revenue`), are delta-scoped refunds (`refund_controller_balance_delta`), or pull *from* the caller. None reads `token.balance(controller)` as spendable.
3. Enumerate governance operations: no op type performs an arbitrary token transfer from the controller.
4. Result: `token.balance(controller) == amount` forever; funds are unrecoverable by any caller.