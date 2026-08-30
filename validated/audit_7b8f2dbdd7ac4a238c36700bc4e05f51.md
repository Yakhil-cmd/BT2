### Title
Orphaned accrued interest captured at 1:1 by the first depositor after `total-supply` returns to zero - (File: `mainnet/contracts/vault/v0-vault-stx.clar` and equivalent vaults `v0-vault-usdc.clar`, `v0-vault-usdh.clar`, `v0-vault-sbtc.clar`, `v0-vault-ststx.clar`, `v0-vault-ststxbtc.clar`)

### Summary
The vault's share-conversion function mints shares 1:1 whenever `total-supply` is zero, without checking whether `total-assets-preview` (which folds in interest accrued on still-outstanding debt) is already non-zero. If the vault's LP share supply drops to zero while there is still unrepaid, interest-accruing debt on the books, the accrued-but-uncollected interest becomes an "orphaned" claim that belongs to no shareholder. The next depositor who arrives is minted shares at a pure 1:1 ratio against that already-inflated `total-assets`, letting them redeem immediately for more than they deposited — capturing value that structurally belongs to the protocol's reserve/treasury cut and to the interest-paying borrower's counterparties, exactly mirroring the `sdeusd.move` "orphaned rewards captured by first staker" pattern.

### Finding Description
`convert-to-shares-preview` treats an empty share supply as license for a naive 1:1 mint, ignoring any existing `total-assets-preview`: [1](#0-0) 

`total-assets-preview` is not merely the physical token balance held by the vault (`assets` var) — it also adds unrealized interest computed from the difference between accrued debt and outstanding principal (`debt - borrowed`), i.e. interest that borrowers owe but have not yet physically repaid: [2](#0-1) 

This unrealized-interest component keeps growing purely from elapsed time via `next-index`/`next-liquidity-index`, independent of whether any shareholder exists: [3](#0-2) 

The reserve/treasury cut of that interest is only minted to `.dao-treasury` proportionally to `total-supply` at the moment `accrue()` runs: [4](#0-3) 

If `total-supply()` is `0` at that instant, `treasury-lp` computes to `0` (since it's multiplied by `total-supply`), so the DAO treasury permanently loses its entitled reserve-factor share of that period's interest. When a new depositor subsequently calls `deposit`, `convert-to-shares-preview` mints their shares at 1:1 against `amount`, while `var-set assets` only adds the *new* deposit amount to the nominal `assets` variable — the pre-existing unrealized interest embedded in `total-assets-preview` is left dangling and now backs the new depositor's shares in full: [5](#0-4) 

Immediately after this deposit, `total-assets` for the vault exceeds `total-supply`'s nominal 1:1 backing by the orphaned interest amount, so the depositor can redeem for strictly more than they put in via `convert-to-assets-preview`, which is symmetric and uses the same `ta`/`ts` ratio: [6](#0-5) [7](#0-6) 

### Impact Explanation
This is theft of unclaimed yield: the DAO treasury's reserve-factor cut of interest that accrued while `total-supply == 0` is never minted to it (the `treasury-lp` calc is proportional to `total-supply`, which was zero), and that same yield is instead extracted in full by whichever address happens to be the first depositor after the empty-supply window. This lands in the **High** impact bucket ("theft of unclaimed yield ... other than unclaimed yield" — explicitly, theft of unclaimed yield). The attacker (any unprivileged depositor) harms a distinct party — the DAO treasury / protocol reserve, whose fee entitlement on that interest is permanently forfeited — via the shared `assets`/`total-supply`/`index` state in the vault contract.

### Likelihood Explanation
Likelihood is Low-to-Medium and depends on the vault actually reaching `total-supply == 0` while outstanding, interest-accruing debt (`total-borrowed > 0`) still exists. Because `redeem` requires `available-assets >= inkind` (a liquidity check against the vault's real token balance), full share-supply exhaustion while material unpaid interest exists on the books is a narrower window than the analogous Move report (which had no such constraint), but it is not structurally prevented: DAO treasury shares (minted from prior periods' reserve cuts) can also be redeemed/transferred away, and low-utilization periods where liquidity comfortably covers the last redeemer's full claim make the zero-supply state reachable. An attacker can monitor for `total-supply` dropping to zero (or engineer it by being the last redeemer themselves) and then immediately deposit to capture the orphaned interest.

### Recommendation
Mirror the report's fix: forbid share-supply from reaching exactly zero while `total-borrowed > 0` (or force a full `accrue()`/treasury settlement and reset of debt-interest accounting when supply reaches zero), or alternatively require `convert-to-shares-preview` to fall back to consuming any pre-existing `total-assets-preview` (rather than a naive 1:1 mint) whenever `total-supply == 0` but `total-assets-preview > 0`, e.g. by permanently locking the orphaned surplus to the DAO treasury before allowing 1:1 minting to resume.

### Proof of Concept
1. Vault has outstanding debt: `total-borrowed = 1000`, and time passes such that `total-debt() = 1050` (50 units of unrealized interest accrued via `next-index`), while `total-supply = 0` (all prior suppliers, including any treasury shares, have exited or none existed yet) and `assets` (nominal, physical) var `= 0`.
   - `total-assets-preview()` = `assets(0) + (debt(1050) - borrowed(1000)) = 50` — see [2](#0-1) .
2. Attacker calls `deposit(100, 0, attacker)`.
   - `accrue()` runs first; since `total-supply() == 0`, `treasury-lp = 0` — the DAO treasury's reserve cut on the 50-unit interest is lost, per [8](#0-7) .
   - `convert-to-shares-preview(100)`: `ts == 0` → returns `100` (1:1), ignoring the pre-existing `ta = 50` — per [9](#0-8) .
   - `var-set assets (+ 0 100) = 100`. `total-supply` becomes `100`.
3. Post-deposit: `total-assets-preview() = assets(100) + (debt-borrowed unrealized interest, still ~50) = 150`, `total-supply = 100`.
4. Attacker immediately calls `redeem(100, 0, attacker)`: `convert-to-assets-preview(100) = ta*100/ts = 150*100/100 = 150`, per [6](#0-5) . The attacker withdraws 150 for a 100 deposit, netting the 50-unit orphaned interest that should have been split between the protocol reserve (DAO treasury) and would-be co-suppliers.

### Citations

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L308-315)
```text
(define-private (convert-to-shares-preview (amount uint))
  (let ((ta (total-assets-preview))
        (ts (total-supply-preview)))
    (if (is-eq ts u0)
        amount
        (if (is-eq ta u0)
            u0
            (mul-div-down amount ts ta)))))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L317-324)
```text
(define-private (convert-to-assets-preview (amount uint))
  (let ((ta (total-assets-preview))
        (ts (total-supply-preview)))
    (if (is-eq ta u0)
        u0
        (if (is-eq ts u0)
            u0
            (mul-div-down amount ta ts)))))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L341-346)
```text
(define-private (total-assets-preview)
  (let ((current-assets (var-get assets))
        (debt (debt-preview))
        (borrowed (var-get total-borrowed))
        (interest (if (> debt borrowed) (- debt borrowed) u0)))
    (+ current-assets interest)))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L379-404)
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
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L763-795)
```text
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
    (asserts! (<= (+ current-assets amount) CAP-SUPPLY) ERR-SUPPLY-CAP-EXCEEDED)

    (try! (receive-underlying amount account))
    (try! (ft-mint? zft inkind recipient))
    (var-set assets (+ current-assets amount))
    
    (print {
      action: "deposit",
      caller: contract-caller,
      data: {
        depositor: account,
        recipient: recipient,
        amount: amount,
        shares-minted: inkind,
        assets: (+ current-assets amount)
      }
    })

    (ok inkind)))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L797-831)
```text
(define-public (redeem (amount uint) (min-out uint) (recipient principal))
  (let (
    (states (var-get pause-states))
    (u (try! (accrue)))
    (account contract-caller)
    (current-assets (var-get assets))
    (balance (get-balance-internal account))
    (balance-check (asserts! (>= balance amount) ERR-INSUFFICIENT-BALANCE))
    (available-assets (get-available-assets))
    (inkind (convert-to-assets-preview amount)))

  (asserts! (>= current-assets inkind) ERR-INSUFFICIENT-ASSETS)
  (asserts! (not (get redeem states)) ERR-PAUSED)
  (asserts! (> amount u0) ERR-AMOUNT-ZERO)
  (asserts! (> inkind u0) ERR-OUTPUT-ZERO)
  (asserts! (>= inkind min-out) ERR-SLIPPAGE)
  (asserts! (>= available-assets inkind) ERR-INSUFFICIENT-LIQUIDITY)

  (try! (ft-burn? zft amount account))
  (try! (send-underlying inkind recipient))
  (var-set assets (- current-assets inkind))
  
  (print {
    action: "redeem",
    caller: contract-caller,
    data: {
      redeemer: account,
      recipient: recipient,
      shares-burned: amount,
      amount-received: inkind,
      assets: (- current-assets inkind)
    }
  })

  (ok inkind)))
```

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L843-859)
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
                (var-set lindex nliq)
                false)
            (if (> treasury-lp u0)
                (try! (ft-mint? zft treasury-lp .dao-treasury))
                false)
```
