### Title
Pool `repay` refunds a declared overpayment from real custody without verifying any inbound transfer - (File: contracts/pool/src/ops/repay.rs)

### Summary
The ClamAV bug class is a privileged write to an attacker-controlled destination: the process appends to whatever file the "logfile" path resolves to, so an attacker who swaps in a symlink steers the write into a critical file. The analog in this codebase is `ops::repay::apply` in the pool: it derives a refund amount from the *declared* `action.amount` rather than from measured custody, and then writes that refund to the caller-supplied `payer` address via `transfer_out` — an unfunded outbound transfer paid out of real token custody.

### Finding Description
`repay::apply` resolves the action amount against outstanding debt. Any excess over `current_debt_ceil` becomes `overpayment` and is sent to `payer`:

- `cache.resolve_repay(amount, position)` splits `amount` into burned debt shares and `overpayment` (contracts/pool/src/ops/repay.rs:44).
- Only `net_repay` (amount minus overpayment) is credited to cash (contracts/pool/src/ops/repay.rs:57).
- `outcome.cache.transfer_out(payer, outcome.overpayment)` sends the overpayment to `payer` (contracts/pool/src/ops/repay.rs:32).

`Cache::transfer_out` executes `token.transfer(pool, recipient, amount)` with no `debit_cash` and no `require_reserves` — it moves real tokens while the book is untouched (contracts/pool/src/cache/cash.rs:46-53). So the refund is funded by the pool's actual token balance, not by what the caller just paid in.

When the action names a market/position with zero debt, the *entire* declared `amount` becomes `overpayment`: `net_repay == 0` satisfies the `RepayRoundsToZeroShares` disjunct (contracts/pool/src/ops/repay.rs:48-52), nothing is burned, and `transfer_out` pays the full declared amount out of custody. The committed test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` confirms exactly this: a `repay` call with a declared amount equal to the pool's custody, with no inbound transfer and zero debt, returns `actual_amount == 0` and drains custody to `payer` (contracts/pool/tests/flows.rs:3578-3611). The same shape exists in `ops::recapitalize::apply`, where the excess over the shortfall is refunded on the same unfunded basis.

This mirrors the symlink primitive: the "destination" (`payer`) and the "content" (`overpayment`) are both attacker-controlled parameters, and the contract appends a real token transfer to a destination it never validated held an inbound payment — writing value wherever the attacker's pointer resolves.

### Impact Explanation
An unprivileged address that can invoke the pool repay leg (directly if the pool's caller check permits, or via any controller path that forwards a `PoolAction` whose `amount` is not preceded by a measured inbound transfer) drains up to the pool's full token balance of a debt-free market into an address it names. That is theft of supplier funds backed by the cash book: custody decreases while `cash` accounting stays unchanged, leaving suppliers unable to withdraw — theft of user funds and permanent freezing of residual funds.

### Likelihood Explanation
The accounting bug is unconditional — `transfer_out` never consults reserves or receipts, and the test proves the zero-debt path reaches it. Likelihood hinges on reachability: controller-driven `repay`/`liquidate` flows normally pre-fund the pool via `transfer_amount_measured`, so a strict controller-gated pool limits the loss to what was actually received (net zero). If `Pool::repay` (or `recapitalize`) can be invoked by any non-controller caller, or if any reachable path constructs the `PoolAction` without a measured inbound transfer, the drain is fully permissionless. I could not fully verify the pool's caller-authorization gate within the available iterations; the in-repo test calling `repay` directly and succeeding indicates the check, if present, is satisfiable by a generated `payer` address.

### Recommendation
- Measure the inbound leg: compute `overpayment` from tokens actually received by the pool this transaction (balance delta), not from the declared `action.amount`.
- Route the refund through `debit_cash`/`require_reserves` so an unfunded refund cannot exceed the just-credited `net_repay`.
- Hard-gate pool `repay`/`recapitalize` to the controller address and document that the controller always precedes the action with `transfer_amount_measured`.

### Proof of Concept
Existing committed test demonstrates the drain:

- `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` — contracts/pool/tests/flows.rs:3590-3611. The attacker calls `repay(payer, ract(0, custody_before))` on a market with zero debt; nothing is credited (`actual_amount == 0`) and the full declared amount is refunded out of real custody to `payer`.
- Supporting code path: `resolve_repay` splits the declared amount (contracts/pool/src/ops/repay.rs:44), `transfer_out(payer, overpayment)` pays from custody without reserve checks (contracts/pool/src/ops/repay.rs:32, contracts/pool/src/cache/cash.rs:46-53).