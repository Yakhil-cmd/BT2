### Title
Fee-on-transfer / short-transfer underlying tokens desynchronize the vault's internal `assets` accounting from real token holdings, letting one depositor's transaction impose an insolvency shortfall on other depositors' redemptions - (File: `mainnet/contracts/vault/v0-vault-usdc.clar` and sibling vaults `v0-vault-sbtc.clar`, `v0-vault-ststx.clar`, `v0-vault-ststxbtc.clar`, `v0-vault-stx.clar`, `v0-vault-usdh.clar`)

### Summary
The Zest v2 vault contracts (Clarity analog of `AdvancedOrderEngine.fillOrders()`) credit the internal accounting variable `assets` with the caller-supplied nominal `amount` on `deposit`, without ever verifying that the vault's real underlying-token balance increased by that same amount. This is exactly the class of bug described in the external report: a function that assumes "amount transferred == amount specified" and updates internal bookkeeping accordingly. Because the vault serves many depositors/redeemers from one shared pool keyed by this single `assets` variable, a mismatch caused by any single caller's deposit is not confined to that caller — it corrupts the shared state consumed by every other, unrelated user who later redeems from the same vault.

### Finding Description
`deposit()` in every vault contract (e.g. `mainnet/contracts/vault/v0-vault-usdc.clar`) does: [1](#0-0) 

It computes `inkind` shares from `convert-to-shares-preview(amount)` — which is based purely on the nominal `amount`, not on any post-transfer balance delta — then calls `receive-underlying`: [2](#0-1) 

and unconditionally executes `(var-set assets (+ current-assets amount))` using the same nominal `amount`, never comparing it against the vault's actual token balance (`ubalance`, defined at lines 301-302 of the same file but only wired into flashloan post-condition checks, not into `deposit`/`redeem`). The share-price and liquidity math for *all* users is driven by `total-assets-preview`, which reads only `(var-get assets)`: [3](#0-2) 

`redeem()` similarly trusts `available-assets`/`current-assets` (derived from the same `assets` var) to gate payouts and then calls `send-underlying inkind recipient`: [4](#0-3) 

If the whitelisted underlying token ever transfers less than the requested `amount` on `receive-underlying` (fee-on-transfer, rounding/rebase quirk, or a future upgrade of a currently-fee-free token such as the bridged `usdcx` or `usdh`), the vault's `assets` variable becomes permanently inflated relative to the tokens it actually holds. `assets` is a single, protocol-wide shared cache: one depositor's transaction primes it with a wrong value, and every other depositor's/redeemer's subsequent `redeem` call (which relies on `available-assets`/`current-assets` derived from that same `assets` var) consumes the corrupted state. This is precisely the "shared index or cache primed by one caller and consumed by another" pattern called out as in-scope: the depositor triggering the mismatch is an unprivileged principal, and the victims are the other unprivileged depositors/redeemers of the same pool whose withdrawals can no longer be fully honored because the real on-chain balance is lower than the accounted `assets`.

### Impact Explanation
This lands on temporary freezing of funds / protocol insolvency for the shared pool: once `assets` overstates real holdings, later redeemers pass the `available-assets`/`current-assets` checks that are computed from the inflated `assets` value, but `send-underlying` can fail or drain the vault's real balance below what remaining depositors are entitled to. The last redeemers in the queue are unable to withdraw their fair share — a shortfall socialized across all depositors of that vault, caused by a single earlier depositor's transaction, not by the victims' own actions.

### Likelihood Explanation
Likelihood is currently constrained by the client's own stated mitigation (whitelisted, currently fee-free/no-short-transfer tokens: STX, sBTC, stSTX, USDC-bridge `usdcx`, USDH, stSTXbtc) — matching the original report's "Acknowledged/Design Choice" status. However, since none of `deposit`/`redeem` in any of the six vault contracts perform a real balance-delta reconciliation (unlike the flashloan path, which does check `ubalance`), the mismatch is immediately exploitable/triggerable the moment any whitelisted underlying token's transfer semantics deviate from "exact amount delivered" — including via a token contract upgrade the DAO does not control, or an edge case in a rebasing/liquid-staking token like `stSTX`/`stSTXbtc` whose exchange-rate/transfer behavior is external to Zest.

### Recommendation
In `receive-underlying`/`send-underlying` (or immediately after calling them in `deposit`/`redeem`), measure the vault's actual token balance before and after the transfer (via `ubalance`) and use the realized delta — not the caller-supplied `amount` — to update `(var-set assets ...)` and to determine shares minted/burned and payout amounts. This closes the accounting gap so no single depositor's transaction can desynchronize the shared `assets` state consumed by other users.

### Proof of Concept
1. Assume (hypothetically, or after a token-contract upgrade) the vault's underlying SIP-010 token starts deducting a transfer fee, e.g. transferring `amount` results in the vault receiving `amount - fee`.
2. User A calls `deposit(amount, min-out, A)` on `v0-vault-usdc.clar`. `receive-underlying` moves `amount - fee` real tokens into the vault, but line `(var-set assets (+ current-assets amount))` credits the vault with the full nominal `amount`. Shares minted to A are computed from the pre-deposit `ta`, so A's own shares are not directly affected, but the pool's stated `assets` now overstates real holdings by `fee`.
3. Time passes; other depositors B, C, ... deposit/redeem normally, each interacting with an `assets` value that is `fee` higher than reality.
4. When the last redeemer(s) call `redeem()`, `available-assets`/`current-assets` (computed from the inflated `assets`) pass the `ERR-INSUFFICIENT-LIQUIDITY`/`ERR-INSUFFICIENT-ASSETS` checks, but `send-underlying` cannot pay out the full amount because the vault's real token balance is short by the accumulated `fee` — freezing/losing funds belonging to those unrelated redeemers, not to depositor A who caused the mismatch.

### Citations

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L291-294)
```text
(define-private (receive-underlying (amount uint) (account principal))
  (begin
    (try! (contract-call? 'SP120SBRBQJ00MCWS7TM5R8WJNTTKD5K0HFRC2CNE.usdcx transfer amount account current-contract none))
    (ok true)))
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L339-344)
```text
(define-private (total-assets-preview)
  (let ((current-assets (var-get assets))
        (debt (debt-preview))
        (borrowed (var-get total-borrowed))
        (interest (if (> debt borrowed) (- debt borrowed) u0)))
    (+ current-assets interest)))
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L761-783)
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
```

**File:** mainnet/contracts/vault/v0-vault-usdc.clar (L799-819)
```text
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
```
