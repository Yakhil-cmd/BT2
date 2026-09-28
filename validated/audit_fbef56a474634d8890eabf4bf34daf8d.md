### Title
Tokens transferred to the controller (or pool, position NFT, governance) are permanently stranded — no retrieval path exists - (File: contracts/controller/src/strategies/migrate_blend.rs)

### Summary
The bug class is "value can be pushed into a contract but no function can pull it back out." In XOXNO Lending this maps onto token balances that land on the controller, pool, position NFT, or governance contract outside a measured flow. Every outbound token movement is a balance-delta measurement against the current call (`transfer_amount_measured`, refund of positive callback deltas, revenue forwarding of the measured receipt). Anything already sitting on the contract before the call is invisible to those measurements, and no in-scope contract exports a `sweep`/`rescue` entrypoint — only the out-of-scope swap aggregator has `sweep_balance` (`contracts/swap-aggregator/src/lib.rs:189-203`).

### Finding Description
- `claim_revenue` forwards exactly the measured receipt; stranded controller dust is untouched by design: `claim_revenue_forwards_the_measured_amount_and_leaves_controller_dust_intact` asserts `controller_after == controller_before` (`tests/test-harness/tests/controller/outbound_transfer_measurement.rs:148-151`).
- `migrate_from_blend` ignores pre-existing controller balances: `test_migrate_refund_ignores_preexisting_controller_balance` pins that stuck controller ETH "must remain (not used as refund or swept)" (`tests/test-harness/tests/strategy/migrate_blend.rs:529-535`).
- `flash_position` refunds only positive callback deltas of refund-listed tokens; "an undeclared token left on the controller is neither deposited nor refunded" (`skills/xoxno-lending-contracts/flash-loans.md:134`), and "refunds cover only positive callback deltas of refund-listed tokens … neither category sweeps prior balances" (`docs/explanation/threat-model.md:172-173`).
- The protocol explicitly guards only the *in-flow* variant: `borrow`/`withdraw` addressed to the pool or controller revert with `InvalidFlashloanReceiver` precisely because "the controller holds funds no balance-delta measurement can ever claim" (`tests/test-harness/tests/controller/recipient_is_protocol_contract.rs:1-5`). Direct `token.transfer` to the controller address — which any token holder can do — is not guarded at all.
- The pool case is weaker: a direct donation to the pool is unbooked but still sits inside the physical custody backing `transfer_out`, so it is absorbed by suppliers/borrowers rather than frozen. The controller, position NFT, governance, and price-aggregator contracts custody nothing legitimately, so any balance there is fully frozen.

### Impact Explanation
Any tokens a user mistakenly transfers directly to the controller (or tokens a flash-position receiver pushes in but omits from the collateral/refund lists) are unrecoverable through the contract ABI. This is permanent freezing of funds, matching the original report's accepted impact. Recovery requires a controller Wasm upgrade executed through governance — the same "needs an upgrade to rescue" framing the original medium finding was accepted on.

### Likelihood Explanation
Reachable by any unprivileged address via a plain `token.transfer(user → controller, amount)`, or organically whenever a flash-position callback delivers a token not declared in the collateral/refund sets (the receiver itself chooses what to send). The codebase's own tests acknowledge stranded controller dust "of the kind a receiver callback can leave behind" (`outbound_transfer_measurement.rs:124-127`). Medium likelihood at best — it depends on user/integrator error — consistent with Medium severity.

### Recommendation
Add a governance-gated rescue entrypoint on the controller that transfers out an arbitrary `(token, amount)` held by the controller, documented to never touch the pool's custody (all legitimate funds live in the pool contract; the controller's own token balances are definitionally stranded). Equivalently, document that receiver contracts must declare every pushed token in the flash-position collateral/refund lists.

### Proof of Concept
1. Deploy the standard harness (`LendingTest::new().standard_two_asset()`).
2. `token.transfer(&alice, &controller, &X)` for any listed or unlisted token — succeeds; controller now holds `X`.
3. Enumerate the controller ABI (`supply, borrow, withdraw, repay, liquidate, clean_bad_debt, flash_loan, flash_position, multiply, swap_debt, swap_collateral, repay_debt_with_collateral, migrate_from_blend, update_indexes, claim_revenue, update_account_threshold, recapitalize`): none performs an unconditional `token.transfer(controller → recipient)`; every outbound leg is a measured delta of the current call, so `X` is never claimable — identical to the pinned behavior in `test_migrate_refund_ignores_preexisting_controller_balance`.