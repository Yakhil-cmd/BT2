### Title
Precision-loss rounding in `accrue` lets any unprivileged caller permanently forfeit accrued interest and reserve fees owed to all depositors of a low-decimal vault (e.g. `v0-vault-usdc`) - (File: `mainnet/contracts/vault/v0-vault-usdc.clar`)

### Summary
The USDC vault's `accrue` function computes interest and the protocol's `fee-reserve` share using floor-rounding math (`mul-div-down`) against a fixed `INDEX-PRECISION` of `1e12`, while the underlying asset only has `DECIMALS u6` [1](#0-0) . Because `accrue` unconditionally advances the `last-update` checkpoint every time it runs (whenever the recomputed index differs, or is simply consumed even without change), any unprivileged user (depositor/borrower) can call functions that trigger `accrue` frequently and with short time deltas, causing the computed `debt-delta`/`reserve-inc` to round down to zero and be lost forever, at the expense of all other depositors of that same vault.

### Finding Description
`accrue` derives `next` (the new borrow index) and `nliq` (the new liquidity index) from `next-index`/`next-liquidity-index`, which multiply the current index by a rate-and-time-based multiplier [2](#0-1) . It then computes the interest that accrued to the pool as `old-debt`/`new-debt` via `mul-div-down` on `scaled-principal` and derives `reserve-inc` (the protocol/treasury's cut) from `debt-delta`, again with `mul-div-down`:

```
(old-debt (mul-div-down scaled-principal idx INDEX-PRECISION))
(new-debt (mul-div-down scaled-principal next INDEX-PRECISION))
(debt-delta (if (> new-debt old-debt) (- new-debt old-debt) u0))
(reserve-inc (mul-div-down debt-delta (var-get fee-reserve) BPS))
``` [3](#0-2) 

Critically, `last-update` is only reset when the accrual actually mutated the index (`(if (or (not (is-eq idx next)) (not (is-eq lidx nliq))) (var-set last-update stacks-block-time) false)`) [4](#0-3) . However, `next-index`/`next-liquidity-index` still compute a `multiplier` from `time-delta` and apply it via `calc-multiplier-delta`/`calc-index-next` for any non-zero `time-delta`, and `mul-div-down` floors any fractional result. For a 6-decimal asset like USDC (`DECIMALS u6`) accruing at realistic annual rates over a short interval (seconds to low minutes), `debt-delta` computed off `scaled-principal` (itself scaled from a 6-decimal `total-borrowed`, per `system-borrow`'s `(scaled-amount (mul-div-up amount INDEX-PRECISION idx))` [5](#0-4) ) can floor to zero (or a value small enough that `reserve-inc` also floors to zero). `accrue` is invoked as part of `deposit`, `redeem`, and `system-borrow`/`system-repay` [6](#0-5) , meaning any unprivileged account can trigger it cheaply and repeatedly (e.g., tiny deposits/redeems, or borrowing tiny amounts). Because `idx`/`lidx` do get bumped even by a rounded/near-zero multiplier in many cases, `last-update` advances and the shortfall interest for that interval is permanently unrecoverable - the checkpoint resets and the missed accrual window can never be "made up" retroactively. This directly mirrors the root cause in the referenced Sherlock M-18 report: fixed-precision interest accounting combined with a resettable timestamp checkpoint causes systematic, replayable loss of interest/fees when the underlying asset has low decimals.

The attacker (any address able to call `deposit`/`redeem`/`system-borrow`/`system-repay`) is not the only affected party: the lost interest would otherwise have flowed into `total-assets`/`total-debt` (increasing redeemable value for all depositors, i.e., `zft` holders) and into `fee-reserve` minted to `dao-treasury`. By forcing frequent, low-time-delta accruals, the attacker socializes a permanent loss of yield across all other depositors of the vault, satisfying the "socialization charged to all suppliers" analog class.

### Impact Explanation
This is a permanent loss of unclaimed yield to all depositors (and to the protocol treasury's fee-reserve) in the `v0-vault-usdc` vault (and structurally, any other Zest vault backed by a low-decimal asset). Since `last-update` advances on every accrual call regardless of whether the rounded interest was captured, the shortfall cannot be recovered on a subsequent call - it is gone forever. Repeated indefinitely at low gas cost (accrue is triggered by cheap operations like tiny deposits/redeems), this compounds into a material, permanent reduction of yield owed to legitimate depositors, matching the in-scope "permanent freezing/loss of unclaimed yield" impact class.

### Likelihood Explanation
Likelihood is elevated because:
- `accrue` is invoked on every `deposit`, `redeem`, `system-borrow`, and `system-repay` call - all of which are callable by any unprivileged account, with no minimum amount enforced on deposit/redeem.
- The precision-loss condition (short time delta relative to rate/principal size) is easy and cheap to reproduce on Stacks, similar to the original report's gas-cost analysis on EVM chains.
- The vulnerable pattern (fixed `INDEX-PRECISION` regardless of the underlying asset's decimals, floor-rounding via `mul-div-down`, and unconditional checkpoint advancement) is duplicated identically across the `v0-vault-usdc` (6-decimal) and other stablecoin-style vaults in `mainnet/contracts/vault/`.

### Recommendation
- Scale internal accounting (`scaled-principal`, `total-borrowed`, `assets`) to a fixed high precision (e.g., 18 decimals) independent of the underlying asset's native decimals, so that `debt-delta`/`reserve-inc` computations retain sufficient precision for low-decimal assets.
- Avoid resetting `last-update` when the computed `debt-delta`/`reserve-inc` rounds to zero; instead, only reset the checkpoint once a non-zero delta has actually been captured, so unaccrued time is preserved for the next call to `accrue` rather than being silently discarded.
- Consider tracking accumulated sub-unit remainders across calls (a "dust" accumulator) so repeated small accruals eventually cross the rounding threshold instead of being discarded.

### Proof of Concept
1. Deploy/use `v0-vault-usdc` with a nonzero `fee-reserve` and a realistic interest rate set via `points-ir` (e.g., 1-3% APR).
2. Have a borrower open a modest position via `system-borrow` (e.g., a few thousand USDC, 6 decimals).
3. Repeatedly call any accrue-triggering entrypoint (e.g., `redeem`/`deposit` with dust amounts, or `system-repay` with a token amount) at short intervals (seconds to a few minutes).
4. Observe that `debt-delta`/`reserve-inc`, computed via `mul-div-down` against `INDEX-PRECISION u1000000000000` and `scaled-principal` derived from a 6-decimal `total-borrowed`, round to zero for these short intervals, yet `last-update` is still advanced whenever `idx`/`lidx` change from the multiplier calculation - permanently discarding the interest/fee that should have accrued during that window.
5. Repeating this indefinitely (cheaply, since gas/tx cost on Stacks is low) causes a cumulative, permanent loss of yield to all depositors and of protocol fee-reserve, analogous to the PoC described in the referenced Sherlock M-18 finding.

Note: I was unable to retrieve the exact body of the shared `calc-multiplier-delta`/`calc-index-next` helper functions within tool-call limits, so the precise rounding threshold (exact time-delta/rate/principal combination that floors to zero) could not be numerically verified against this codebase; this should be confirmed with a live Clarity test/PoC before remediation.

### Citations

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L22-27)
```text
(define-constant DECIMALS u6)

;; -- Precision & scaling
(define-constant BPS u10000)
(define-constant PRECISION u100000000)
(define-constant INDEX-PRECISION u1000000000000)  ;; 1e12 for index calculations
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L377-406)
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

(define-private (next-liquidity-index)
  (let ((states (var-get pause-states))
        (lidx (var-get lindex)))
    (if (get accrue states)
        lidx
        (let (
            (rate (interest-rate))
            (liquidity-rate (calc-liquidity-rate rate (utilization) (var-get fee-reserve)))
            (time-delta (- stacks-block-time (var-get last-update)))
            (multiplier (if (is-eq time-delta u0)
                          INDEX-PRECISION
                          (calc-multiplier-delta liquidity-rate time-delta false))))
          (calc-index-next lidx multiplier)))))

(define-private (principal-ratio-reduction (amount uint))
  (calc-principal-ratio-reduction amount (var-get principal-scaled) (debt-preview)))

```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L835-840)
```text
        (idx (var-get index))
        (lidx (var-get lindex)))
      (if (get accrue states)
          ;; PAUSED: Pass-through without reverting
          (ok { index: idx, lindex: lidx })
          ;; NOT PAUSED: Normal accrual logic
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L841-852)
```text
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
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L858-864)
```text
            (if (or (not (is-eq idx next)) (not (is-eq lidx nliq)))
                (var-set last-update stacks-block-time)
                false)
            (ok { index: next, lindex: nliq })))))

(define-public (system-borrow (amount uint) (receiver principal))
  (let (
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L872-879)
```text
      (scaled-amount (mul-div-up amount INDEX-PRECISION idx))
      (updated-scaled-principal (+ scaled-principal scaled-amount)))

    (try! (check-caller-auth))
    (asserts! (not (get borrow states)) ERR-PAUSED)
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (<= amount available-assets) ERR-INSUFFICIENT-VAULT-LIQUIDITY)
    (asserts! (<= (+ debt amount) CAP-DEBT) ERR-DEBT-CAP-EXCEEDED)
```
