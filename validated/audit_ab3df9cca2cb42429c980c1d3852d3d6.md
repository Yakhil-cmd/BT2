### Title
Unbacked sBTC bond-share crediting from unchecked `sbtc-token transfer` return value in `roll-sbtc` - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5.clar`'s private function `roll-sbtc`, called from `register-for-bond` and `update-bond-registration`, moves sBTC into contract custody by calling `(try! (contract-call? ... sbtc-token transfer delta tx-sender current-contract none))` and then unconditionally increments `total-sbtc-staked` and the staker's `amount-sats` in `protocol-bond-memberships`. `try!` only aborts on `(err ...)`; it does not verify that the wrapped `ok` value is `true`. This is the same class of bug as the Trail of Bits finding in the SORA/Ethereum bridge, where `token.transferFrom`'s boolean return value was never checked, letting a token that returns `false` on failure (instead of reverting) be credited as if the transfer succeeded.

### Finding Description
In `roll-sbtc`: [1](#0-0) 

the increase branch does:
```
(try! (contract-call?
    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
    transfer delta tx-sender current-contract none))
(var-set total-sbtc-staked (+ (var-get total-sbtc-staked) delta))
```
`try!` unwraps `(ok bool)` responses and only short-circuits on `(err ..)`. If `sbtc-token`'s `transfer` function ever returns `(ok false)` on a failed transfer (rather than an `err`), the `try!` call succeeds with the discarded `false` value, and `roll-sbtc` proceeds to record the deposit as if it happened. `register-for-bond` then unconditionally writes the claimed `sats-total`/`amount-sats` into `protocol-bond-memberships` and bumps `protocol-bonds-total-staked`/`total-sbtc-staked`: [2](#0-1) 

This breaks the equality "sBTC physically custodied by pox-5" == "sBTC accounted for in `total-sbtc-staked` / per-cycle staker shares". The per-cycle sBTC shares drive reward distribution (`calculateRewards`/`settle-rewards`), so a staker who registers a `delta` that silently fails to transfer would still receive `staker-shares-staked-for-cycle` credit and earn sBTC rewards proportional to `sats-total`, diluting rewards actually backed by other stakers' real sBTC.

This is out-of-scope only insofar as the *sbtc-token contract's* internal transfer semantics are concerned (rule excludes issues purely inside `sbtc-token`), but here the root cause is `pox-5.clar`'s own failure to validate the boolean result of a fungible-token transfer before crediting stake — exactly the "pox-5's own use of sbtc-token" carve-in the rules permit.

### Impact Explanation
If exploitable (i.e., if any accepted `sbtc-token` implementation can return `(ok false)` rather than erroring on a failed transfer — a plausible SIP-010 implementation detail, mirroring the BAT/HT/CHSB/cUSDC ERC20 precedent in the original report), a staker can register/increase a protocol bond position and be credited `amount-sats`/`total-sbtc-staked` shares without actually contributing sBTC. This is unbacked minting of a reward-bearing commitment: the staker earns sBTC rewards from `calculateRewards` proportional to a non-existent deposit, which dilutes and effectively steals reward-pool funds from honest stakers who supplied real sBTC — a Critical-tier double-counting/unbacked-crediting condition per the rules ("sBTC rewards paid that were not earned or counted twice").

### Likelihood Explanation
The likelihood is contingent entirely on `sbtc-token`'s `transfer` semantics returning `(ok false)` on failure instead of `(err ..)` — the native `ft-transfer?` cannot do this, but a custom/proxy `sbtc-token` contract (analogous to the audited ERC20 tokens with non-conforming return semantics) could. `pox-5.clar` performs no additional check that would catch this even if it happened, so the vulnerability's presence is entirely a function of the token contract, but the vulnerable *usage pattern* is squarely in `pox-5.clar` and warrants a defensive fix regardless of current `sbtc-token` behavior.

### Recommendation
In `roll-sbtc` (and any other `contract-call? ... transfer ...` invocation of `sbtc-token` in `pox-5.clar`), explicitly assert the unwrapped boolean is `true` before mutating `total-sbtc-staked` / membership state, e.g.:
```clarity
(asserts! (try! (contract-call? 'SM3....sbtc-token transfer delta tx-sender current-contract none))
          ERR_SBTC_TRANSFER_FAILED)
```
instead of relying on bare `try!`, so that a token returning `(ok false)` is treated as a failed transfer and the stake/bond state is never credited.

### Proof of Concept
1. Assume (or deploy on testnet, since `sbtc-token` is configurable per `set_pox_5_sbtc_contract`) a stand-in `sbtc-token` whose `transfer` function returns `(ok false)` when the sender's balance is insufficient, instead of `(err ..)`.
2. Attacker calls `register-for-bond` with `btc-lockup` set to `(err desired-sats)` and `amount-ustx` sufficient to pass the STX check, while holding zero/insufficient sBTC balance.
3. `roll-sbtc` computes `delta = new-sbtc - old-sbtc = desired-sats` and calls `sbtc-token transfer` — which returns `(ok false)` since the attacker has no sBTC.
4. `try!` unwraps `false` and discards it; execution continues.
5. `protocol-bond-memberships` records `amount-sats: desired-sats`, and `total-sbtc-staked`/`protocol-bonds-total-staked` are incremented by `desired-sats`, even though the attacker's sBTC balance and the contract's sBTC balance are unchanged.
6. At the next reward cycle, the attacker's bond share entitles them to a proportional cut of `calculateRewards`, diluting genuine stakers' rewards without ever having deposited sBTC.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L782-796)
```text
        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))

        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
            amount-sats: sats-total,
        })
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
        ;; A roll-over from an ending bond ADDS the new bond's shares but does
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1943-1979)
```text
(define-private (roll-sbtc
        (staker principal)
        (old-sbtc uint)
        (new-sbtc uint)
    )
    (begin
        (if (> new-sbtc old-sbtc)
            (let ((delta (- new-sbtc old-sbtc)))
                (try! (contract-call?
                    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                    transfer delta tx-sender current-contract none
                ))
                (var-set total-sbtc-staked (+ (var-get total-sbtc-staked) delta))
            )
            (if (< new-sbtc old-sbtc)
                (let ((delta (- old-sbtc new-sbtc)))
                    (try! (as-contract?
                        ((with-ft
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            "sbtc-token" delta
                        ))
                        (try! (contract-call?
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            transfer delta tx-sender staker none
                        ))
                    ))
                    (var-set total-sbtc-staked
                        (- (var-get total-sbtc-staked) delta)
                    )
                )
                ;; new-sbtc == old-sbtc, no transfer needed
                true
            )
        )
        (ok true)
    )
)
```
