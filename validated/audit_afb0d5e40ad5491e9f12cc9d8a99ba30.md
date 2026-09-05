### Title
`update-bond-registration` hardcodes `num-cycles=u1` when validating the new signer, letting a multi-cycle bond re-assignment bypass the signer's true authorization check - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
In `update-bond-registration`, the staker's actual multi-cycle re-commitment to a new signer is computed as `num-cycles` and is what's actually applied to state (`add-staker-to-signer-cycles`, `add-staker-to-bond-cycles`), but the call that is supposed to get the new signer's/its manager's authorization for taking on this staker (`signer-manager-validate-stake`) is passed a hardcoded `u1` instead of `num-cycles`.

### Finding Description
`update-bond-registration` computes the real duration of the re-assignment as: [1](#0-0) 

and then calls: [2](#0-1) 

passing `u1` as the number-of-cycles argument to `signer-manager-validate-stake`, instead of `num-cycles`. Yet the very next lines apply the *real* `num-cycles` value to state: [3](#0-2) 

Every other call site that commits a staker to a signer for multiple cycles (`stake`, `stake-update`) correctly passes the real `num-cycles` to the validation/registration trait calls, e.g.: [4](#0-3) 

`signer-manager-validate-stake` is the hook that lets a signer-manager contract (the signer's own authorization/allowlist/cap logic) accept or reject a staker's commitment based on how many cycles and how much sats/uSTX are being committed. By always passing `u1` here, the new signer-manager is deceived into evaluating (and potentially authorizing) only a single-cycle, `amount-sats`-sized commitment, while the staker is actually locked into that signer for `num-cycles` cycles (up to the full remaining bond term, since `bond-end-cycle` can be several cycles away and `BOND_LENGTH_CYCLES` bonds span multiple cycles as seen elsewhere in the contract, e.g. `first-reward-cycle` to `bond-end-cycle` in `register-for-bond`). Any cap or duration-sensitive logic in the signer-manager trait (e.g. "accept at most N sats-cycles" or "reject commitments longer than K cycles") is bypassed, letting the staker commit sats/shares to the new signer for a duration the signer's manager never actually validated/authorized.

### Impact Explanation
This is a stacking action (re-assigning a multi-cycle sBTC-bond and STX delegation to a new signer) that the signer/signer-manager never truly authorized, since the manager is asked to approve a 1-cycle commitment while the contract locks in a `num-cycles` commitment. A signer-manager relying on the passed cycle count to bound its exposure (its cap logic, reward-slot sizing, or admission checks) can be tricked into hosting more shares/cycles than it agreed to, which can cause signing weight/reward slots to exceed what was actually validated — matching the High-severity class "signing weight or reward slots exceeding locked value, an unsigned stacking action."

### Likelihood Explanation
Any bond participant calling `update-bond-registration` to switch signers triggers this path unconditionally; it does not require a malicious admin, miner, or another user's key — only the staker's own authority over their own bond membership, which is in scope per the unprivileged-account rule.

### Recommendation
Pass the real `num-cycles` computed at line 870 to `signer-manager-validate-stake` instead of the hardcoded `u1`:
```clarity
(try! (signer-manager-validate-stake signer-manager tx-sender bond-index num-cycles
    (get amount-ustx current-membership) amount-sats true
    signer-calldata
))
```

### Proof of Concept
1. Alice registers for a bond (`register-for-bond`) with `bond-index` B, locking `amount-sats` sats and committing for the full bond term; `bond-end-cycle` is several cycles in the future.
2. Well before `bond-end-cycle`, Alice calls `update-bond-registration` to move to a new `signer`. At this point `num-cycles = bond-end-cycle - first-reward-cycle` is large (e.g. 5 cycles), but `signer-manager-validate-stake` is invoked with the literal `u1`.
3. The new signer's manager contract evaluates the request as if Alice is only committing for 1 cycle and approves accordingly (e.g., under a per-cycle sats cap that would have rejected a 5-cycle commitment).
4. `remove-staker-from-cycles` / `add-staker-to-signer-cycles` / `add-staker-to-bond-cycles` are then executed with the real `num-cycles`, locking Alice's sats/uSTX shares into the new signer across all 5 cycles — a commitment the signer-manager's validation logic never actually saw or approved.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L862-870)
```text
            (bond-start-cycle (bond-period-to-reward-cycle bond-index))
            (bond-end-cycle (bond-period-to-reward-cycle (+ bond-index u6)))
            (next-cycle (+ current-cycle u1))
            ;; If the bond hasn't started yet, then the first cycle where
            ;; this new signer is active is the start cycle. Otherwise, it's the next reward
            ;; cycle, unless the bond will be over at that point.
            (first-reward-cycle (clamp next-cycle bond-start-cycle bond-end-cycle))
            (amount-sats (get amount-sats current-membership))
            (num-cycles (- bond-end-cycle first-reward-cycle))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L883-887)
```text
        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            (get amount-ustx current-membership) amount-sats true
            signer-calldata
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L903-919)
```text
        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender first-reward-cycle num-cycles false))

        ;; Re-add to existing cycles with the new signer
        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            num-cycles (get amount-ustx current-membership) false
        ))

        ;; Remove the sBTC shares from the current signer
        (try! (remove-staker-from-bond-cycles tx-sender current-signer bond-index
            first-reward-cycle num-cycles amount-sats
        ))

        ;; Add the sBTC shares to the current signer
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            num-cycles amount-sats
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1116-1120)
```text
        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender
            first-reward-cycle num-cycles new-lock-amount u0 false
            signer-calldata
        ))
```
