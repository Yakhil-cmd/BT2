### No vulnerability found for this question.

The described behavior is normal shared-pool economics, not a defect. `deposit` in every vault contract (e.g. [1](#0-0) ) enforces a single global cap check `(asserts! (<= (+ current-assets amount) CAP-SUPPLY) ERR-SUPPLY-CAP-EXCEEDED)` against a shared `assets` variable that any depositor's transaction updates via `(var-set assets (+ current-assets amount))`. This is a first-come-first-served shared resource by design: whoever's transaction lands first (in any block) consumes available headroom, exactly like liquidity being consumed in a lending pool, which the rules explicitly classify as ordinary shared-pool economics and out of scope ("Reject ordinary shared-pool economics... liquidity being consumed").

Additionally, the premise itself is inconsistent with the code: `cap-supply` is a fixed configuration variable set by the DAO, not something that increases "via each accrue-driven CAP-SUPPLY increase" — `accrue` only updates `index`/`last-update`/interest accounting, it never touches `cap-supply`. There is no mechanism by which A can repeatedly regain headroom purely from accrual; headroom only opens when someone redeems (reducing `assets`), which is normal pool dynamics available to any principal, not an exploit unique to A.

Since B's only loss is being unable to deposit into an already-full cap — the same outcome that would occur if any other ordinary user (not just an "attacker") filled the cap first — there is no non-consensual manipulation of state beyond intended cap semantics, and no distinguishable attacker profit or unique bug path. [2](#0-1)

### Citations

**File:** local-testing/contracts/vault/vault-usdc.clar (L765-797)
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
