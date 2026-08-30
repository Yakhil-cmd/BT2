Confirmed: `deposit` has no `ERR-OUTPUT-ZERO` check (unlike `redeem`), and `min-out` defaults to caller-supplied value — if the caller (or a naive/default UI flow) passes `min-out u0`, a deposit that computes `inkind` (shares) equal to `u0` will pass the `(asserts! (>= inkind min-out) ERR-SLIPPAGE)` check and proceed to mint zero shares while still pulling in and crediting the underlying asset.

### Title
Zero-share deposit at full utilization silently donates depositor funds to existing shareholders - (File: `mainnet/contracts/vault/v0-vault-sbtc.clar` and equivalent vault contracts)

### Summary
`convert-to-shares-preview` returns `u0` whenever `total-assets-preview` (`ta`) is `u0` while `total-supply-preview` (`ts`, i.e. outstanding shares) is non-zero, instead of reverting. `deposit` uses this value as `inkind` and only guards against zero via `(asserts! (>= inkind min-out) ERR-SLIPPAGE)`, unlike `redeem`, which explicitly checks `(asserts! (> inkind u0) ERR-OUTPUT-ZERO)`. If a depositor (or default client) supplies `min-out u0`, a deposit made while `ta == 0` and `ts != 0` mints zero shares yet still transfers the underlying in and increases `assets`, silently transferring the depositor's funds to existing shareholders.

### Finding Description
`convert-to-shares-preview` in each vault (e.g. [1](#0-0) ) is:
```
(define-private (convert-to-shares-preview (amount uint))
  (let ((ta (total-assets-preview)) (ts (total-supply-preview)))
    (if (is-eq ts u0)
        amount
        (if (is-eq ta u0)
            u0
            (mul-div-down amount ts ta)))))
```
This mirrors the flawed assumption in the LybraFinance `EUSD.mint`/`getSharesByMintedEUSD` bug: the code treats a computed value of `0` as a special sentinel ("no shares exist yet, mint 1:1") without re-checking whether the *other* side of the ratio (`ts`, i.e. shares outstanding) is actually non-zero. Here it's the inverse edge — `ta == 0` while `ts != 0` — but the same class of bug: a zero-branch is reachable by a state (full utilization / vault temporarily has 0 idle assets while `total-borrowed` == accrued `debt`, see [2](#0-1) ) that is neither the "totalSupply == 0 bootstrap" case nor an error, yet is handled identically to a hard failure, and the caller path (`deposit`) does not reject the zero result the way `redeem` does.

`deposit` ( [3](#0-2) ) computes `inkind` via `convert-to-shares-preview`, then only asserts `(>= inkind min-out)`, `(> amount u0)`, cap, pause, and reentrancy checks — never `(> inkind u0)`. Compare `redeem` ( [4](#0-3) , specifically line 809), which explicitly reverts with `ERR-OUTPUT-ZERO` if the output amount is zero. `deposit` is missing this symmetric protection.

### Impact Explanation
Victim = the depositor calling `deposit` with `min-out u0` (or any `min-out` a naive client computes from an off-chain zero preview) while the vault is fully utilized (`ta == 0`, `ts != 0`). Attacker = any existing shareholder (or the vault's natural operating state) who benefits: the depositor's underlying asset is pulled via `receive-underlying` and added to `assets` (line 779), backing all existing shares, but the depositor receives `0` shares from `ft-mint?` (line 778). Without the bug, the depositor would either be reverted (correct behavior, analogous to `redeem`'s `ERR-OUTPUT-ZERO`) or receive shares proportional to their deposit; with the bug, their principal is fully and permanently transferred to the pool with no shares issued — a direct loss of funds at rest for one unprivileged party for the benefit of others, matching the Critical impact class (theft/permanent loss of user funds).

### Likelihood Explanation
Full utilization (`total-assets-preview == 0` while shares outstanding) is a reachable, foreseeable operating state for a lending vault (100% of assets borrowed with no interest accrued yet since last accrual). It doesn't require any privileged action or DAO compromise — it can occur naturally or be induced by borrowers. The main mitigating factor is that the depositor (or the calling client/frontend) must supply `min-out u0` (or a stale non-zero-derived `min-out` that still permits zero output) instead of a positive slippage bound; a well-behaved frontend that always previews and sets `min-out > 0` would catch it via `ERR-SLIPPAGE`. This makes the likelihood moderate rather than trivial, since it depends on caller/client input, but the missing on-chain invariant is a real gap since `redeem` codifies this exact protection while `deposit` does not.

### Recommendation
Add an explicit `(asserts! (> inkind u0) ERR-OUTPUT-ZERO)` check in `deposit` (mirroring `redeem`), in every vault contract (`v0-vault-sbtc.clar`, `v0-vault-ststx.clar`, `v0-vault-ststxbtc.clar`, `v0-vault-stx.clar`, `v0-vault-usdc.clar`, `v0-vault-usdh.clar`), so that a deposit can never silently mint zero shares regardless of the caller-supplied `min-out`.

### Proof of Concept
1. Vault has `ts` (shares outstanding) `> 0` (some prior depositors) and enters a state where `total-borrowed == debt` and `assets == 0` (fully utilized, no interest accrued since last `accrue`), so `total-assets-preview` returns `u0`.
2. A new depositor calls `deposit(amount, min-out: u0, recipient)`.
3. `inkind = convert-to-shares-preview(amount)` evaluates the `(is-eq ta u0)` branch and returns `u0` [1](#0-0) .
4. `(asserts! (>= inkind min-out) ERR-SLIPPAGE)` passes since `u0 >= u0`.
5. `receive-underlying amount account` pulls in the depositor's tokens; `ft-mint? zft inkind recipient` mints `0` shares; `assets` is increased by `amount` [5](#0-4) .
6. Result: depositor's `amount` is now backing all outstanding shares held by other users, but the depositor holds `0` shares of the vault — an irreversible loss for the depositor, socialized as a gain to existing shareholders.

### Citations

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L306-313)
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

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L332-343)
```text
(define-private (total-assets)
  (let ((current-assets (var-get assets))
        (debt (total-debt))
        (borrowed (var-get total-borrowed))
        (interest (if (> debt borrowed) (- debt borrowed) u0)))
    (+ current-assets interest)))

(define-private (total-assets-preview)
  (let ((current-assets (var-get assets))
        (debt (debt-preview))
        (borrowed (var-get total-borrowed))
        (interest (if (> debt borrowed) (- debt borrowed) u0)))
```

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L761-793)
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

**File:** mainnet/contracts/vault/v0-vault-sbtc.clar (L795-829)
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
