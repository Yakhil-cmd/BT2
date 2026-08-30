### Title
Compounding-frequency-dependent interest index lets any unprivileged caller overcharge borrowers and inflate treasury/LP minting via `accrue` - (File: mainnet/contracts/vault/v0-vault-stx.clar and sibling vault contracts)

### Summary
Zest's vault contracts (`v0-vault-stx.clar`, `v0-vault-sbtc.clar`, `v0-vault-ststx.clar`, `v0-vault-ststxbtc.clar`, `v0-vault-usdc.clar`, `v0-vault-usdh.clar`) implement the exact discrete-compounding pattern flagged in the Flayer report: a per-second linear rate is applied over an arbitrary, caller-triggered time window and then multiplicatively compounded into a shared `index`/`lindex` state variable. Because any unprivileged account can trigger a checkpoint (`accrue`) at will simply by calling `deposit`, `system-borrow`, `system-repay`, or `transfer`, the effective annualized interest rate charged to borrowers (and credited to the reserve/treasury) depends on how often unrelated third parties checkpoint the vault, not on the nominal per-annum rate configured by the DAO.

### Finding Description
`calc-multiplier-delta` computes a simple ("linear") interest multiplier for the elapsed `time-delta` since the last checkpoint: [1](#0-0) 

`next-index` then feeds this multiplier into `calc-index-next`, which multiplies it onto the *previous* `index`: [2](#0-1) [3](#0-2) 

This is structurally identical to the flagged Flayer formula `compoundedFactor_ = previous * (1 + rate*dt) / 1e18`: it compounds a per-period *simple*-interest increment onto the running index every time a checkpoint occurs. The checkpoint (`accrue`) is invoked — and `index`/`lindex`/`last-update` persisted — inside the shared `accrue` routine: [4](#0-3) 

Crucially, `accrue` is called at the top of essentially every state-mutating public entrypoint that ordinary, unprivileged users can invoke, including `system-borrow`: [5](#0-4) 
and `deposit`/`transfer` in the sibling contract source (identical accrue-call pattern): [6](#0-5) 

Because `index` is compounded once per checkpoint using the *linear* factor for that checkpoint's elapsed time, and checkpoints can be forced arbitrarily often by any account performing trivial deposits/repayments/transfers, the effective annualized rate applied to `principal-scaled` (via `calc-cumulative-debt`, used in `total-debt`/`debt-preview`) rises toward `e^r` as checkpoint frequency n → ∞ (since `(1+r/n)^n` is monotonically increasing in n for fixed r). A borrower who never interacts with the vault after taking out a loan is nonetheless charged interest that depends on the checkpoint frequency imposed by *other, unrelated* accounts' unprivileged transactions — the classic "shared index primed by one caller, consumed by another" pattern.

The same checkpoint also computes `reserve-inc`/`treasury-lp` from the debt delta between the old and new index and mints extra `zft` treasury LP tokens to `.dao-treasury`: [7](#0-6) 
Any inflation of the compounded debt delta caused purely by checkpoint frequency (rather than genuine elapsed time/APR) translates directly into extra treasury LP minted, further diluting/benefiting depositors at the borrower's expense beyond the nominal configured rate.

### Impact Explanation
Borrowers are charged interest whose effective annualized rate is not fixed by the DAO-configured per-annum rate curve, but instead scales with how frequently unrelated, unprivileged users checkpoint the vault (deposit, borrow, repay, or transfer). A single passive borrower with a static position can have their debt compounded far more (or less) than intended purely due to third-party activity they cannot control, resulting in theft of unclaimed/accrued yield from the borrower to the depositor pool and treasury — matching the "High: theft of unclaimed yield" impact class. Because every one of the six vault contracts (`v0-vault-stx`, `v0-vault-sbtc`, `v0-vault-ststx`, `v0-vault-ststxbtc`, `v0-vault-usdc`, `v0-vault-usdh`) shares this identical `accrue`/`next-index`/`calc-multiplier-delta` pattern, the issue affects the entire lending surface of the protocol.

### Likelihood Explanation
No special privilege or attack setup is required: any account can call `deposit`, `system-borrow`, `system-repay`, or `transfer` at will, each of which invokes `accrue`. High-frequency checkpointing can happen organically (active markets with many small transactions) or be deliberately induced by any user (e.g., spamming minimal deposits/repayments) to force more frequent compounding, so the divergence from the intended nominal rate is not a rare edge case but a systemic property of the interest accounting design.

### Recommendation
Replace the discrete multiplicative "simple-interest-per-checkpoint" compounding with a formula whose result is independent of checkpoint frequency, e.g.:
- Track cumulative "continuously compounded" growth using a closed-form exponential approximation (e.g. Taylor-series `e^x` as used in Aave-style `MathUtils.calculateCompoundedInterest`) so that `index` after any given elapsed real time is the same regardless of how many intermediate checkpoints occurred, or
- If non-compounding (simple) interest is intended, accumulate additively (`index += rate * dt / year`) rather than multiplicatively re-applying the per-period rate onto the compounded index.
Either fix removes the dependency of the effective rate on unrelated third-party checkpoint frequency and prevents the resulting reserve/treasury-LP over-minting side effect.

### Proof of Concept
Given a fixed configured annual rate `r` for a vault (via `interest-rate`/`points-ir`):
1. Borrower A opens a loan via `system-borrow`.
2. Scenario 1 (low frequency): No further activity occurs for one year; A's own repayment triggers a single `accrue` call, applying `next-index` once with `time-delta = 365 days`, giving multiplier `≈ 1 + r`.
3. Scenario 2 (high frequency): An unrelated, unprivileged account repeatedly calls trivial `deposit`/`system-repay`/`transfer` operations every day for the same year, each invoking `accrue`, so `index` is recompounded 365 times with `multiplier_i ≈ 1 + r/365` each time.
4. Because `calc-index-next` multiplies the running `index` by each period's multiplier (`mainnet/contracts/vault/v0-vault-stx.clar:183-184, 379-390`), the cumulative multiplier in Scenario 2 approaches `(1+r/365)^365 ≈ e^r`, which for large `r` is substantially larger than the `1+r` obtained in Scenario 1 — reproducing the same magnitude of divergence (up to tens of percent, escalating with `r`) documented in the original Flayer report, purely as a function of third-party checkpoint frequency that Borrower A has no control over.

Note: the exact numeric divergence depends on the DAO-configured rate curve (`points-ir`) for each vault, which is set via privileged DAO calls and not directly inspectable from the static contract text alone; the qualitative frequency-dependence of the formula itself is confirmed directly from the cited `calc-multiplier-delta`/`calc-index-next`/`accrue` code.

### Citations

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L170-178)
```text
(define-private (calc-multiplier-delta (rate uint) (time-delta uint) (round-up bool))
  (+ INDEX-PRECISION
    (if round-up
      (mul-div-up rate
                  (* time-delta INDEX-PRECISION)
                  SECONDS-PER-YEAR-BPS)
      (mul-div-down rate
                  (* time-delta INDEX-PRECISION)
                  SECONDS-PER-YEAR-BPS))))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L183-184)
```text
(define-private (calc-index-next (index-curr uint) (multiplier uint))
  (mul-div-down index-curr multiplier INDEX-PRECISION))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L379-390)
```text
(define-private (next-index)
  (let ((states (var-get pause-states))
        (idx (var-get index)))
    (if (get accrue states)
        idx
        (let (
            (rate (interest-rate))
            (time-delta (- stacks-block-time (var-get last-update)))
            (multiplier (if (is-eq time-delta u0)
                          INDEX-PRECISION
                          (calc-multiplier-delta rate time-delta true))))
          (calc-index-next idx multiplier)))))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L841-871)
```text
          (ok { index: idx, lindex: lidx })
          ;; NOT PAUSED: Normal accrual logic
          (let ((next (next-index))
                (nliq (next-liquidity-index))
                (scaled-principal (var-get principal-scaled))
                (old-debt (mul-div-down scaled-principal idx INDEX-PRECISION))
                (new-debt (mul-div-down scaled-principal next INDEX-PRECISION))
                (debt-delta (if (> new-debt old-debt) (- new-debt old-debt) u0))
                (reserve-inc (mul-div-down debt-delta (var-get fee-reserve) BPS))
                (treasury-lp (if (> reserve-inc u0) (mul-div-down reserve-inc (total-supply) (- (total-assets-preview) reserve-inc)) u0)))
            (if (not (is-eq idx next))
                (var-set index next)
                false)
            (if (not (is-eq lidx nliq))
                (var-set lindex nliq)
                false)
            (if (> treasury-lp u0)
                (try! (ft-mint? zft treasury-lp .dao-treasury))
                false)
            (if (or (not (is-eq idx next)) (not (is-eq lidx nliq)))
                (var-set last-update stacks-block-time)
                false)
            (ok { index: next, lindex: nliq })))))

(define-public (system-borrow (amount uint) (receiver principal))
  (let (
      (states (var-get pause-states))
      (u (try! (accrue)))
      (CAP-DEBT (var-get cap-debt))
      (available-assets (get-available-assets))
      (scaled-principal (var-get principal-scaled))
```

**File:** local-testing/contracts/vault/vault-ststxbtc.clar (L756-780)
```text
(define-public (transfer (amount uint) (from principal) (to principal) (memo (optional (buff 34))))
  (begin
    (try! (accrue))
    (asserts! (or (is-eq tx-sender from) (is-eq contract-caller from)) (err u4))
    (asserts! (not (is-eq current-contract to)) ERR-TOKENIZED-VAULT-PRECONDITIONS)
    (try! (ft-transfer? zft amount from to))
    (match memo to-print (print to-print) 0x)
    (ok true)))

;; -- Vault operations -------------------------------------------------------

(define-public (deposit (amount uint) (min-out uint) (recipient principal))
    (let (
      (states (var-get pause-states))
      (u (try! (accrue)))
      (account contract-caller)
      (CAP-SUPPLY (var-get cap-supply))
      (current-assets (var-get assets))
      (inkind (convert-to-shares-preview amount)))

    (asserts! (not (get deposit states)) ERR-PAUSED)
    (asserts! (var-get initialized) ERR-INIT)
    (asserts! (not (var-get in-flashloan)) ERR-REENTRANCY)
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (>= inkind min-out) ERR-SLIPPAGE)
```
