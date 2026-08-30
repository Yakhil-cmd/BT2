### Title
zToken Transfers Bypass All Pause Checks, Letting Holders Offload Non-Redeemable Shares onto Unaware Counterparties - ([File: mainnet/contracts/vault/v0-vault-stx.clar])

### Summary
Every Zest vault (`v0-vault-stx.clar`, `v0-vault-sbtc.clar`, `v0-vault-ststx.clar`, `v0-vault-usdc.clar`, `v0-vault-usdh.clar`, `v0-vault-ststxbtc.clar`) exposes a `pause-states` var that can independently disable `deposit`, `redeem`, `borrow`, `repay`, `accrue`, and `flashloan` [1](#0-0) . `deposit` and `redeem` both check their respective pause flag before executing [2](#0-1) [3](#0-2) . However, `transfer` performs no check whatsoever against `pause-states` — it only validates the caller and that the recipient isn't the vault contract itself [4](#0-3) . This is the exact analog of the Primitive Option bug: a claim token (zToken) continues to be freely transferable even while the operation that gives it economic value (`redeem`) is disabled by the protocol.

### Finding Description
The vault's zToken (e.g. `zSTX`, `zUSDC`) represents a claim on underlying assets that is only realizable via `redeem`. When the DAO pauses `redeem` on a vault (e.g., due to a detected accounting issue, an oracle problem, or an emergency halt while investigating a shortfall), holders of that vault's zToken are unable to withdraw the underlying asset. Nothing in `transfer` reflects this state:

```
(define-public (transfer (amount uint) (from principal) (to principal) (memo (optional (buff 34))))
  (begin
    (try! (accrue))
    (asserts! (or (is-eq tx-sender from) (is-eq contract-caller from)) (err u4))
    (asserts! (not (is-eq current-contract to)) ERR-TOKENIZED-VAULT-PRECONDITIONS)
    (try! (ft-transfer? zft amount from to))
    ...
``` [5](#0-4) 

Because a paused-for-redeem zToken is indistinguishable on-chain (via `transfer`, DEX pools, or supply-collateral flows) from a freely redeemable one, an attacker who is aware of the pending pause (e.g., a large depositor who observes suspicious vault behavior, or who has advance knowledge of an upcoming DAO pause) can immediately transfer/sell zTokens to an unaware counterparty — either directly, through a liquidity pool, or by using the token as collateral within `market.clar`'s `collateral-add`/`supply-collateral-add` flows, which accept zTokens without querying the vault's pause state. The victim receives a token that appears to be a normal, redeemable share but cannot actually be converted back to the underlying asset for as long as the pause is active.

### Impact Explanation
The victim (an unaware buyer/counterparty of the zToken) suffers a temporary freezing of funds: their capital is locked in a token they believed was redeemable and liquid, while the attacker who initiated the transfer offloads the risk before or during the pause window. This mirrors the impact class of the original finding (temporary freezing of unclaimed funds for the counterparty), independent of the attacker's own position.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to have or suspect advance knowledge of a redeem pause (which the DAO can trigger for legitimate emergency reasons) and a counterparty willing to accept the zToken without checking `pause-states` first (e.g., automated market makers, other integrators, or users unaware of the pause). Since `pause-states` is a public read-only value, sophisticated actors can react to a pause the instant it's observed, front-running less-informed holders/buyers.

### Recommendation
Add a check in `transfer` (and any internal `ft-transfer?` paths) that blocks transfers while `redeem` (and optionally `deposit`) is paused, similar to the checks already present in `deposit`/`redeem`. Since the report notes tokens may still need to move back to the vault/market contract during emergency operations, carve out an explicit exception for transfers whose destination is the vault or market contract itself, while blocking transfers to arbitrary third parties during a redeem pause.

### Proof of Concept
1. DAO detects an issue with `v0-vault-usdc` and calls the pause-setting function to disable `redeem` (pause-states.redeem = true).
2. Attacker, who already holds `zUSDC`, immediately calls `transfer` to send `zUSDC` to Bob (an OTC buyer) or deposits it into a liquidity pool, in exchange for other liquid assets — `transfer` succeeds because it performs no pause check [5](#0-4) .
3. Bob later calls `redeem` to withdraw the underlying USDC and it reverts with `ERR-PAUSED` [3](#0-2) , leaving Bob holding frozen `zUSDC` while the attacker has already exited into liquid funds.

### Citations

**File:** mainnet/contracts/vault/v0-vault-stx.clar (L98-115)
```text
;; -- Pause states
(define-data-var pause-states
  {
    deposit: bool,
    redeem: bool,
    borrow: bool,
    repay: bool,
    accrue: bool,
    flashloan: bool
  }
  {
    deposit: false,
    redeem: false,
    borrow: false,
    repay: false,
    accrue: false,
    flashloan: false
  })
```

**File:** mainnet/contracts/vault/v0-vault-ststx.clar (L752-759)
```text
(define-public (transfer (amount uint) (from principal) (to principal) (memo (optional (buff 34))))
  (begin
    (try! (accrue))
    (asserts! (or (is-eq tx-sender from) (is-eq contract-caller from)) (err u4))
    (asserts! (not (is-eq current-contract to)) ERR-TOKENIZED-VAULT-PRECONDITIONS)
    (try! (ft-transfer? zft amount from to))
    (match memo to-print (print to-print) 0x)
    (ok true)))
```

**File:** mainnet/contracts/vault/v0-vault-ststx.clar (L772-776)
```text
    (asserts! (not (get deposit states)) ERR-PAUSED)
    (asserts! (var-get initialized) ERR-INIT)
    (asserts! (not (var-get in-flashloan)) ERR-REENTRANCY)
    (asserts! (> amount u0) ERR-AMOUNT-ZERO)
    (asserts! (>= inkind min-out) ERR-SLIPPAGE)
```

**File:** mainnet/contracts/vault/v0-vault-ststx.clar (L808-810)
```text
  (asserts! (>= current-assets inkind) ERR-INSUFFICIENT-ASSETS)
  (asserts! (not (get redeem states)) ERR-PAUSED)
  (asserts! (> amount u0) ERR-AMOUNT-ZERO)
```
