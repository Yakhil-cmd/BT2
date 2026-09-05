### Title
Stale aggregate counter written after an untrusted external `signer-manager-trait` call in `register-for-bond` allows double-counting of staked sats — (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`register-for-bond` in `pox-5.clar` snapshots the cycle's aggregate stake counter (`current-total-staked`) *before* making an external `contract-call?` into an attacker-controllable `signer-manager-trait` contract, and then writes the new aggregate back using that stale snapshot *after* the external call returns. This is the same bug class as the ERC20Pods `_removeAllPods` finding: a value that must reflect the *current* state is cached before a hand-off to attacker-controlled code and used un-refreshed afterward, letting the external call desynchronize the accounting.

### Finding Description
In `register-for-bond`: [1](#0-0) 

`current-total-staked` is read into the `let` binding before any external call is made.

The function then makes a `contract-call?` into the caller-supplied `signer-manager` contract via `signer-manager-validate-stake`: [2](#0-1) [3](#0-2) 

`signer-manager` is an arbitrary contract implementing `signer-manager-trait`, registered via `register-signer`, which only checks a signer-key grant, not that the contract's code is trusted or bounded: [4](#0-3) 

A reentrancy guard (`signer-manager-call-active` / `ERR_REENTRANT_CALL`) is enforced, but it only blocks a *second* call that itself goes through `signer-manager-validate-stake` (i.e., nested `validate-stake!` invocations): [5](#0-4) 

It does **not** generically block re-entering the contract through any other public entry point that mutates `protocol-bonds-total-staked` without going through `signer-manager-validate-stake`. Because Clarity permits synchronous callbacks within one transaction, the attacker's `validate-stake!` implementation executes *while `register-for-bond` is still on the call stack*, with `current-total-staked` already captured in a local binding.

After the external call returns, the function writes the aggregate using the stale value instead of re-reading it: [6](#0-5) 

If the attacker's `signer-manager` contract, during `validate-stake!`, triggers any other pox-5 code path that legitimately mutates `protocol-bonds-total-staked` for the same `bond-index` (e.g., another staker's concurrent bond exit/removal path reachable without going through the `signer-manager-validate-stake` guard), that mutation is silently clobbered by the stale `(+ current-total-staked sats-total)` write once `register-for-bond` resumes — reintroducing sats that should have been removed, or otherwise desynchronizing `protocol-bonds-total-staked` from the true sum of active members' `amount-sats`. This breaks the invariant that `protocol-bonds-total-staked[bond-index]` equals the sum of all active `protocol-bond-memberships` `amount-sats` for that bond, which is precisely the kind of "double-counting a commitment" equality break called for in scope.

I was not able to fully enumerate every other public function that mutates `protocol-bonds-total-staked` (the file exceeds the tool's 1000-line read limit and further `grep_search` calls for related identifiers returned no matches, which is inconsistent with the content directly observed via `read_file` — this suggests indexing gaps for this file). This means the exact secondary reentry path that clobbers the counter could not be conclusively identified in this pass, and should be verified against the full contract source before treating this as fully proven.

### Impact Explanation
If exploitable, this allows a staker (via a self-controlled `signer-manager` contract) to cause `protocol-bonds-total-staked` to diverge from the real aggregate of staked sats — a double-counted commitment. Depending on how downstream reward/allocation logic consumes this aggregate, this could inflate the apparent bond capacity or reward share attributable to sats that are not actually locked, which maps to the "double-counting a commitment or reward" Critical category.

### Likelihood Explanation
Exploitation requires the attacker to control (or collude with) a `signer-manager` contract that has passed `register-signer`'s signer-key-grant check, and to find a second pox-5 entry point that mutates `protocol-bonds-total-staked` for the same `bond-index` without tripping the `signer-manager-call-active` guard. The signer-key-grant requirement raises the bar somewhat, but is achievable by any staker willing to deploy their own signer contract and grant it a key. Confirming a concrete second entry point requires reading the remainder of `pox-5.clar` beyond line 1000, which was not accessible in this session.

### Recommendation
Re-read `current-total-staked` (and any other shared aggregate/state used in a `map-set`) immediately before writing it, rather than relying on a value captured before an external `contract-call?`. Alternatively, broaden the reentrancy guard so that *any* state-mutating call into pox-5 is blocked while a `signer-manager-trait` call is in flight, not just nested `validate-stake!` calls.

### Proof of Concept
Conceptual sequence (pending confirmation of the exact second entry point due to incomplete file visibility):
1. Attacker deploys a `signer-manager` contract, obtains a valid `signer-key-grant`, and calls `register-signer`.
2. Attacker calls `register-for-bond` for `bond-index`, which captures `current-total-staked` for that bond/cycle.
3. Inside `signer-manager-validate-stake`'s external call, the attacker's `validate-stake!` triggers another pox-5 code path (not gated by `signer-manager-call-active`) that legitimately decrements `protocol-bonds-total-staked[bond-index]` (e.g., an unrelated staker's removal being processed in the same transaction via a contract-caller chain, if such a path exists).
4. `register-for-bond` resumes and executes `(map-set protocol-bonds-total-staked bond-index (+ current-total-staked sats-total))` using the pre-call `current-total-staked`, overwriting the decrement from step 3 and leaving the aggregate double-counting sats that should have been removed.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L400-427)
```text
(define-private (validate-no-reentrancy)
    (ok (asserts! (not (var-get signer-manager-call-active)) ERR_REENTRANT_CALL))
)

;; A helper function to call the `validate-stake!` function on a given
;; signer-manager, wrapping the reentrancy guard logic around it. This should
;; be the only way that `validate-stake!` is called in the contract, since it
;; is critical to ensure that reentrancy attacks are prevented.
(define-private (signer-manager-validate-stake
        (signer-manager <signer-manager-trait>)
        (staker principal)
        (first-index uint)
        (num-indexes uint)
        (amount-ustx uint)
        (amount-sats uint)
        (is-bond bool)
        (signer-calldata (optional (buff 500)))
    )
    (begin
        (asserts! (not (var-get signer-manager-call-active)) ERR_REENTRANT_CALL)
        (var-set signer-manager-call-active true)
        (try! (contract-call? signer-manager validate-stake! staker first-index
            num-indexes amount-ustx amount-sats is-bond signer-calldata
        ))
        (var-set signer-manager-call-active false)
        (ok true)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L700-708)
```text
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
            (bond-start-height (bond-period-to-burn-height bond-index))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle BOND_LENGTH_CYCLES))
            (current-total-staked (get-total-shares-staked-for-cycle first-reward-cycle
                (some bond-index)
            ))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L753-756)
```text
        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            amount-ustx sats-total true signer-calldata
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L793-795)
```text
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L945-972)
```text
;; Register a signer
(define-public (register-signer
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
    )
    (let ((signer (contract-of signer-manager)))
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Because signers can have members register at any time,
        ;; they must use signer key grants instead of per-tx
        ;; authorizations.
        (try! (verify-signer-key-grant signer signer-key))

        ;; Only the signer contract itself can register itself
        (asserts! (is-eq contract-caller signer)
            ERR_UNAUTHORIZED_SIGNER_REGISTRATION
        )

        (map-set signers signer signer-key)
        (let ((result {
                signer: signer,
                signer-key: signer-key,
            }))
            (print (merge { topic: "register-signer" } result))
            (ok result)
        )
    )
```
