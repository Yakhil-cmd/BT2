### Title
Repay overpayment refund is paid from pool custody above the measured inbound receipt — ([File: contracts/pool/src/ops/repay.rs](contracts/pool/src/ops/repay.rs))

### Summary
`ops::repay::apply` resolves the overpayment from the **declared** `action.amount` and pays the excess back to the payer out of pool token custody via `Cache::transfer_out`, without debiting `cash` or passing `require_reserves`. On a market whose asset takes a transfer fee (the protocol explicitly supports fee-on-transfer markets), the caller's inbound `token.transfer(payer -> pool, amount)` delivers less than `amount`, but the refund is computed on the gross `amount`. The difference is paid out of supplier-backed custody. Repeating the call drains the pool's real token balance without touching the cash book.

### Finding Description
- `repay::accounting` splits the action into `net_repay` (credited to cash, burns debt shares) and `overpayment` (`contracts/pool/src/ops/repay.rs` L40–67). `repay::apply` then calls `outcome.cache.transfer_out(payer, outcome.overpayment)` (L25–34). The codebase itself documents the gap: "Neither refund debits `cash` or passes `require_reserves` … the whole amount is refunded out of real custody with the book untouched" (`contracts/pool/tests/flows.rs` L3578–3588, demonstrated by `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` at L3590).
- Inbound funding for repay is **not measured** in the pool; the pool trusts `action.amount`. The controller's other inbound legs do measure — `markets::recapitalize` uses `payments::transfer_amount_measured` before calling the pool (`contracts/controller/src/markets.rs` L142–164), and liquidation repayments pull `received` measured amounts (`contracts/controller/src/positions/liquidation/apply.rs` L54–77). The plain repay path instead relies on a caller-authorized `token.transfer(payer -> pool, amount)` for the exact declared amount, then passes that declared amount through — so a fee-on-transfer asset makes `action.amount > actual pool receipt`.
- The same shape exists in `ops::recapitalize::apply` (`contracts/pool/src/ops/recapitalize.rs` L26–38), but the controller mitigates it there by measuring. For repay, an unprivileged user calls `controller.repay(caller, account_id, payments)` on any (hub, token) market after authorizing the inbound transfer; if the market asset is fee-on-transfer (explicitly supported — `with_fee_on_transfer_market` fixtures, and the liquidation refund test at `tests/test-harness/tests/controller/liquidation_band_full_close.rs` L65–111 shows FoT repay measurement handling), each over-repay burns the token's fee out of custody while the cash book records the full declared repay.

### Impact Explanation
Each call converts the token's transfer fee into an unfunded refund paid from pool custody: pool token balance drops by `fee(amount)` more than `cash` accounts for, silently eroding supplier backing. Repeated calls scale the drain arbitrarily → theft of user funds / creeping protocol insolvency (cash book vs. custody divergence is exactly what `INV-ACCT-02/03` are meant to prevent, per `docs/reference/invariants.md` L102–124).

### Likelihood Explanation
Requires a fee-on-transfer market to exist (the codebase supports and tests them) and a user simply over-repaying a debt — a normal, unprivileged operation. No privileged role, oracle manipulation, or exotic preconditions are needed; the loss accrues per transfer fee rate on every over-repay.

### Recommendation
Make the repay refund basis the measured receipt, consistent with the other inbound legs: have the controller measure the inbound transfer (`transfer_amount_measured` / `balance_delta_since`) and pass the measured amount into `pool.repay`, or have the pool compute `overpayment` from `min(action.amount, measured_receipt)`. At minimum, route the refund through the same measured-receipt discipline that `INV-ACCT-03` documents for repayment, so `overpayment` can never exceed what actually arrived.

### Proof of Concept
1. Deploy a market on a fee-on-transfer token (as in `with_fee_on_transfer_market`, fee = f bps).
2. BOB supplies; ALICE borrows debt `D`.
3. ALICE over-repays with declared amount `A > D` via `controller.repay`, authorizing `token.transfer(ALICE -> pool, A)`. The pool receives `A·(1−f)`.
4. `resolve_repay` computes `overpayment = A − D` on the gross `A`; `transfer_out` sends `A − D` back to ALICE.
5. Net pool custody delta: `A·(1−f) − D − (A − D) = −A·f` while `cash` is credited `D` — each iteration removes `A·f` of real tokens with no book debit. Repeating drains reserves below tracked cash.