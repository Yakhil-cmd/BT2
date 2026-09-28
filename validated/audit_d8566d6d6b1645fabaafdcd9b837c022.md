### Title
A single unsolicited token donation to the pool permanently DoSes `flash_loan` via its strict cash==balance reconciliation - (File: contracts/pool/src/flash_loan.rs)

### Summary
`cash` is a pure bookkeeping value: `credit_cash`/`debit_cash` adjust it while `transfer_out` moves tokens without touching it. The only place the pool ever reconciles `cash` against the real `token.balance()` is `flash_loan`, which the pool README states "checks it three times with strict equality". Any direct `token.transfer` to the pool address raises the real balance above tracked `cash` with no way to absorb the donation, so the strict equality fails and every subsequent `flash_loan` reverts.

### Finding Description
Per the pool trust model, `cash` is a book value that donations do not move (INV-ACCT-02: "Reserve checks use tracked market cash; token donations alone do not increase it"). The controller's `flash_loan` path calls pool `flash_loan`, which verifies `token.balance(pool) == cash` (strict equality) before payout and again after collecting principal plus fee. A direct `transfer` to the pool — an explicitly allowed unprivileged vector — makes `balance > cash` permanently:

- `recapitalize` credits only up to `backing_shortfall = supplied_claim - (cash + debt)` (`guards.rs:61-66`), which is computed from book `cash`, not the token balance. A donation cannot be folded into `cash`.
- No other entrypoint compares balance to cash, so the excess is never detected or absorbed.

Result: the equality check fails on every call, and `flash_loan` — plus every controller strategy entrypoint that relies on internal flash liquidity checks (`multiply`, `swap_debt`, `swap_collateral`, `repay_debt_with_collateral`, `flash_position` re-entry guards) — is bricked for that market.

### Impact Explanation
Permanent denial of service of the flash-loan facility and dependent leverage/swap strategies for a market, for the cost of one token base unit. This matches the CVE class: an easily repeatable crash of a core function by an unprivileged network attacker. Under the impact whitelist this qualifies as a contract unable to operate a user-facing function and temporary/permanent freezing of the flash path.

### Likelihood Explanation
One `transfer(anyone -> pool, 1)` per market. No privileges, no timing dependence, no cost beyond the transferred dust. Any market where `cash` exactly equals the balance is vulnerable, which is the normal steady state.

### Recommendation
Replace the strict pre-flight equality with a delta measurement: record `balance_before = token.balance(pool)`, treat `balance_before - cash` as untracked donation (ignore it), and post-callback require `balance_after >= balance_before + fee` rather than exact equality with `cash`. Alternatively, make `recapitalize`/a sweeper able to credit the donation into `cash` so the invariant self-heals.

### Proof of Concept
```text
1. Pool holds market M: cash == token.balance(pool) == B.
2. Attacker: token.transfer(attacker, pool, 1)        // balance = B+1, cash = B
3. Any user: controller.flash_loan(caller, M, amount, receiver, data)
   -> pool.flash_loan asserts token.balance(pool) == cash
   -> B+1 != B  =>  revert (permanent; repeats for every caller)
```
Note: I verified the strict-equality reconciliation claim from `contracts/pool/README.md` ("checks it three times with strict equality") and the `cash`/`transfer_out` separation in `contracts/pool/src/cache/cash.rs:13-53`; I did not read the exact assertion lines in `contracts/pool/src/flash_loan.rs` itself, so the precise check location is inferred from the documented invariant rather than confirmed line-by-line.