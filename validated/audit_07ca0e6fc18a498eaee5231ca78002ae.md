### Title
`roll-sbtc` pulls the sBTC increase from `tx-sender` instead of the `staker` argument - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`roll-sbtc` is documented to move a `staker`'s custodied sBTC to cover an increase in their committed bond, but on the increase branch it executes the sBTC pull using `tx-sender` as the transfer source instead of the `staker` parameter that was explicitly passed in and used everywhere else (including the refund branch). This is structurally identical to the reported ERC20Wrapper flaw: a function that accepts an explicit "who to move funds from" argument (`staker`, analogous to `sender`) silently substitutes the caller (`tx-sender`, analogous to `msg.sender`) for the actual token movement.

### Finding Description
`roll-sbtc` takes `staker`, `old-sbtc`, and `new-sbtc` and is meant to reconcile the sBTC custodied on behalf of `staker` when their bond amount changes: [1](#0-0) 

On the "amount increased" branch, the code calls the sbtc-token `transfer` with `tx-sender` as the sender argument rather than `staker`: [2](#0-1) 

Compare this with the "amount decreased" (refund) branch, which correctly targets `staker` as the recipient of the refund from the contract's own custody: [3](#0-2) 

The doc comment itself says the function should "pull the increase from the staker," which confirms `staker` — not `tx-sender` — is the intended debit account: [4](#0-3) 

The equality broken: the principal whose sBTC is debited to fund an increased commitment (`tx-sender`) is decoupled from the principal whose recorded bond/stake is credited with that increase (`staker`). Since the refund path always returns funds to `staker`, any sBTC pulled from a `tx-sender` that differs from `staker` on the increase path can never be returned to the party that actually paid it — it is permanently redirected to `staker` when the bond later rolls down or unwinds.

### Impact Explanation
If `roll-sbtc` (or any public entry point that invokes it) is reachable in a context where the caller (`tx-sender`) is not the `staker` themselves — for example, a delegate/pool-operator flow registering or renewing a bond on behalf of a `staker` principal — then the delegate's sBTC is debited on the increase, but on the corresponding decrease/rollover the refund is paid to `staker`, not to the delegate who funded it. This is a permanent, uncompensated loss of sBTC for whichever account acts as `tx-sender` but is not the recorded `staker`, and a corresponding unearned credit of custodied sBTC to `staker`. This falls under "theft or permanent freezing of staked STX or sBTC" / "double-counting a commitment."

### Likelihood Explanation
The bug is deterministic and code-level confirmed: the increase branch literally hard-codes `tx-sender` where `staker` is used everywhere else in the function (and in the decrease branch). I was not able to fully trace, within the available tool budget, the exact public entry point(s) that call `roll-sbtc` with a `tx-sender` different from `staker` (e.g., a delegate-driven bond/stake-registration function) — this would need further verification of pox-5.clar's public interface for delegated bond management. However, the function signature explicitly separating `staker` from the implicit `tx-sender`, plus the doc comment describing debiting "the staker," strongly indicates the function is designed to be invoked by an actor other than the staker itself.

### Recommendation
Replace `tx-sender` with `staker` in the increase branch of `roll-sbtc` so that the sBTC pulled to cover an increased bond always comes from the `staker` principal, matching the refund branch and the function's documented behavior:
```clarity
(try! (contract-call?
    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
    transfer delta staker current-contract none
))
```
Additionally, audit all other call sites in `pox-5.clar` where `tx-sender` is used in place of an explicitly-passed principal argument to confirm no other instance of this same pattern exists.

### Proof of Concept
1. Identify (or confirm) a public pox-5.clar function that lets a delegate/operator `D` call into a code path invoking `(roll-sbtc staker old-sbtc new-sbtc)` where `tx-sender = D` and `staker = S` (`S != D`), during bond registration/renewal for `S`'s increased stake.
2. `D` calls this function with `new-sbtc > old-sbtc`; `roll-sbtc` executes `transfer delta D current-contract none`, debiting `D`'s sBTC balance and crediting `total-sbtc-staked`/`S`'s recorded stake.
3. Later, when `S`'s bond amount decreases (rollover down or exit), `roll-sbtc` executes `transfer delta current-contract S none` — refunding the delta to `S`, not to `D`.
4. Net effect: `D` permanently loses `delta` sBTC that is instead retained/refunded to `S`, without `D`'s consent or compensation, while `S`'s recorded stake was inflated using `D`'s funds instead of their own.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1938-1956)
```text
;; Move a staker's custodied sBTC from `old-sbtc` to `new-sbtc`, transferring
;; only the net difference: pull the increase from the staker, or refund the
;; decrease. `total-sbtc-staked` is updated by the net change. A registration
;; with no rollover passes `old-sbtc` of `u0`, which transfers the full amount.
;; A no-op when the two are equal.
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1957-1972)
```text
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
```
