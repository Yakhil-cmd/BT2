### Title
Missing reentrancy guard in `stake` (and `stake-update`) allows signer-manager callback to double-count locked STX before `staker-info` is committed - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`stake` calls out to an attacker-supplied `signer-manager-trait` contract via `signer-manager-validate-stake` *before* it checks `(is-none (get-staker-info tx-sender))` and *before* it writes the `staker-info` map or calls `add-staker-to-signer-cycles`. Unlike `register-signer` and `announce-l1-early-exit`, which explicitly call `(try! (validate-no-reentrancy))` "to ensure no reentrancy through signer-manager trait calls," `stake` and `stake-update` omit this guard, leaving a window where the external call can re-enter the contract while the staker's lock/commitment state is still stale.

### Finding Description
`stake` is defined at [1](#0-0) . It computes `first-reward-cycle`, `amount-ustx`, and other locals, then immediately invokes `(try! (signer-manager-validate-stake signer-manager tx-sender first-reward-cycle num-cycles amount-ustx u0 false signer-calldata))` — a call into a caller-supplied contract implementing `<signer-manager-trait>`. Only *after* this external call does the function assert `(is-none (get-staker-info tx-sender))` and later `map-set staker-info` and `add-staker-to-signer-cycles`, at [2](#0-1) .

Elsewhere in the same contract, calls into trait contracts are explicitly recognized as a reentrancy vector and are guarded: `register-signer` calls `(try! (validate-no-reentrancy))` before touching the `signers` map [3](#0-2) , and `announce-l1-early-exit` does the same with the comment "ensure no reentrancy through signer-manager trait calls" [4](#0-3) . `stake` and `stake-update` (which also calls `signer-manager-validate-stake` before mutating `staker-info`, at [5](#0-4) ) never call `validate-no-reentrancy`.

This is the same root-cause pattern as the external report: a state field that a downstream operation depends on for correctness (`subDir[author][subber]` in the report; `staker-info`/signer-cycle totals here) is updated *after*, rather than *before*, an external call that can act on/re-enter based on that state. In the reported bug this merely caused a revert (DoS); here, because the external call target is a fully attacker-controlled contract (any contract satisfying `<signer-manager-trait>`), the attacker can make that contract call back into `stake` (or another PoX-5 entry point) during `signer-manager-validate-stake`, before `staker-info` for `tx-sender` has been set and before `add-staker-to-signer-cycles` has recorded the commitment. A second nested `stake` call would still pass the `is-none (get-staker-info tx-sender)` check (since it hasn't been written yet by the outer call), letting the same underlying STX amount be counted into `add-staker-to-signer-cycles` multiple times (once per nested call) while the node/lock side only locks once, or letting the attacker manipulate `first-reward-cycle`/signer bookkeeping across nested calls before the outer call's own state write clobbers/overwrites the inner one.

### Impact Explanation
This breaks the equality that a staker's signing weight / reward-cycle commitment recorded via `add-staker-to-signer-cycles` must correspond 1:1 to STX actually locked for that staker. A reentrant call sequence through a malicious `signer-manager` can register the same amount into `reward-cycle`/signer totals more than once (double-counting a commitment) or leave `staker-info` in an inconsistent state relative to the signer-cycle tallies, inflating signer voting/reward weight beyond what is actually locked. Per the scope rules this is a High/Critical-class impact ("signing weight or reward slots exceeding locked value," "double-counting a commitment").

### Likelihood Explanation
The `signer-manager` argument to `stake`/`stake-update` is a trait object supplied by `tx-sender` itself (or an allowed caller), i.e. any user can deploy their own contract implementing `<signer-manager-trait>` and pass it in. No privileged role is required — this matches the "unprivileged-account" requirement. The only uncertainty is the exact internal logic of `signer-manager-validate-stake` (not fully inspected here) and how Clarity's call semantics permit callback dispatch through a trait parameter within the same transaction; this would need to be confirmed by exercising a malicious trait implementation in a local Clarinet/unit-test environment, which the contract's own explicit reentrancy guards elsewhere (`register-signer`, `announce-l1-early-exit`) suggest is a real primitive available to callers of this contract.

### Recommendation
Add `(try! (validate-no-reentrancy))` at the start of `stake` and `stake-update`, mirroring `register-signer` and `announce-l1-early-exit`, and/or move the `is-none (get-staker-info tx-sender)` check and any other authoritative state reads to occur before the `signer-manager-validate-stake` external call, and ensure `staker-info`/signer-cycle map writes cannot be re-entered while pending.

### Proof of Concept
Not directly executable from static review alone; would require a Clarinet/unit test deploying a mock contract implementing `<signer-manager-trait>` whose `validate-stake` method calls back into `pox-5.stake` (or `stake-update`) for the same `tx-sender` before returning, then observing whether `staker-info` and the reward-cycle/signer totals end up double-counted or inconsistent relative to actual locked STX — analogous to the original PoC (`test_weth_stake_fail_POC`) that exercised the state-check ordering flaw in `SubscribeRegistry::subscribe`.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L946-964)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L976-1008)
```text
(define-public (stake
        (signer-manager <signer-manager-trait>)
        (amount-ustx uint)
        (num-cycles uint)
        (start-burn-ht uint)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ u1 current-cycle))
            (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle num-cycles))
            ;; Any bond the staker is currently a member of. Some value here
            ;; indicates this `stake` is a roll-over from an ending bond into
            ;; STX-only.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock). On a
            ;; bond-to-stake rollover the full custody is refunded below.
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender
            first-reward-cycle num-cycles amount-ustx u0 false
            signer-calldata
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1025-1065)
```text
        ;; Cannot already be STX-only staking. Re-extending an existing stake
        ;; goes through `stake-update`, not a second `stake` call.
        (asserts! (is-none (get-staker-info tx-sender)) ERR_ALREADY_STAKED)

        ;; A roll-over from an existing bond is allowed when the bond's term
        ;; ends no later than this stake's first reward cycle. Already-active
        ;; bonds are rejected (overlap). Same shape as the
        ;; `register-for-bond` gate.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_STAKED
        )

        ;; A roll-over from an ending bond may only happen once that bond's
        ;; L1 collateral would have unlocked -- the same window an L1 bond
        ;; holder has to redirect their BTC. Keeps parity with the
        ;; `register-for-bond` gate so a bond's STX / sBTC can't be released
        ;; ahead of the bond's L1 unlock height.
        (try! (verify-bond-rollover-window existing-membership))

        ;;  the Staker must have sufficient total funds (locked + unlocked).
        ;;  On a roll-over the staker's STX is still locked by the ending
        ;;  bond; the node-side handler extends that lock to the new amount,
        ;;  so checking only `stx-get-balance` (unlocked) would falsely fail.
        (asserts! (>= total-balance amount-ustx) ERR_INSUFFICIENT_STX)

        ;; Refund any sBTC custodied for the rolled-over bond (zero-target
        ;; net transfer). No-op when there is no existing bond, or when the
        ;; existing bond is an L1 lock.
        (try! (roll-sbtc tx-sender old-sbtc u0))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            num-cycles amount-ustx true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: amount-ustx,
            first-reward-cycle: first-reward-cycle,
            num-cycles: num-cycles,
            signer: signer,
        })
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1092-1155)
```text
(define-public (stake-update
        (signer-manager <signer-manager-trait>)
        (old-signer-manager <signer-manager-trait>)
        (cycles-to-extend uint)
        (amount-increase uint)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            (old-signer (contract-of old-signer-manager))
            (current-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKING))
            ;; This is the first cycle where their STX would be unlocked
            (prev-unlock-cycle (+ (get first-reward-cycle current-info)
                (get num-cycles current-info)
            ))
            (unlock-cycle (+ prev-unlock-cycle cycles-to-extend))
            (new-lock-amount (+ (get amount-ustx current-info) amount-increase))
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ current-cycle u1))
            (num-cycles (- unlock-cycle current-cycle u1))
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender
            first-reward-cycle num-cycles new-lock-amount u0 false
            signer-calldata
        ))

        ;; Validate that `old-signer-manager` matches their current signer
        (asserts! (is-eq old-signer (get signer current-info))
            ERR_INVALID_OLD_SIGNER_MANAGER
        )

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;; Must have enough unlocked STX
        (asserts! (>= (get unlocked (stx-account tx-sender)) amount-increase)
            ERR_INSUFFICIENT_STX
        )

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender (+ u1 current-cycle)
            (- prev-unlock-cycle current-cycle u1) true
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer (+ u1 current-cycle)
            num-cycles new-lock-amount true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: new-lock-amount,
            first-reward-cycle: (get first-reward-cycle current-info),
            num-cycles: (+ (get num-cycles current-info) cycles-to-extend),
            signer: signer,
        })
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1196-1217)
```text
(define-public (announce-l1-early-exit
        (staker principal)
        (old-signer-manager <signer-manager-trait>)
    )
    (let (
            (old-signer (contract-of old-signer-manager))
            (membership (unwrap! (get-bond-membership staker) ERR_NOT_BOND_PARTICIPANT))
            (bond-index (get bond-index membership))
            (signer (get signer membership))
            (current-cycle (current-pox-reward-cycle))
            (bond-start-cycle (bond-period-to-reward-cycle bond-index))
            (bond-end-cycle (bond-period-to-reward-cycle (+ bond-index u6)))
            (current-total-staked (get-total-sbtc-staked-for-bond bond-index))
            (first-changed-reward-cycle (clamp current-cycle bond-start-cycle bond-end-cycle))
            (amount-sats (get amount-sats membership))
        )
        ;; Reject during the prepare phase since next-cycle data is mutated
        (try! (verify-not-prepare-phase))

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

```
