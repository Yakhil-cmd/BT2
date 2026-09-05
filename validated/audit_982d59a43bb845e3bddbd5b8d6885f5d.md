### Title
Front-runnable `set-burnchain-parameters` initializer allows unprivileged corruption of pox-5's core cycle/bond timing state - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
`set-burnchain-parameters` in `pox-5.clar` is the one-time initializer that sets the reward-cycle and bond-period timing constants used throughout the contract, but it performs no caller authentication — only a "has this run before" guard. Any account can call it first and permanently poison these parameters before the legitimate deployer/governance transaction lands.

### Finding Description
`set-burnchain-parameters` is guarded only by the `configured` boolean, with no `asserts!` on `contract-caller`/`tx-sender`: [1](#0-0) 

Compare this with every other privileged setter in the same contract (`set-bond-admin`, `set-pause-admin`, `pause-rewards`, `setup-bond`), each of which explicitly checks `(asserts! (is-eq contract-caller (var-get bond-admin/pause-admin)) ERR_UNAUTHORIZED)`: [2](#0-1) [3](#0-2) 

`set-burnchain-parameters` writes `first-burnchain-block-height`, `pox-prepare-cycle-length`, `pox-reward-cycle-length`, `first-pox-5-reward-cycle`, and `first-bond-period-cycle` — the fundamental constants that `bond-period-to-burn-height`, `bond-period-to-reward-cycle`, and the reward-cycle math throughout the contract all depend on. This is exactly the "unprivileged initializer" bug class described in the external report: an instruction that sets critical, unrecoverable configuration state has no check that the caller is the intended, trusted deployer/admin, so anyone can race the legitimate setup transaction and win because it can only be called once (`(var-get configured)` guard prevents any later correction).

The test harness explicitly acknowledges (and works around) the exposure this creates in production: it notes that at boot time the tx-sender for boot contract deployment is an unsignable principal, and it must be overridden with a real key purely for testability, and separately confirms `set-burnchain-parameters` has no caller restriction in the contract by never asserting a caller check for it (unlike `setup-bond`, `set-bond-admin`, `set-pause-admin`, which all have companion "rejects non-admin" tests): [4](#0-3) [5](#0-4) 

### Impact Explanation
Because these values are set exactly once and then permanently locked in (`(var-set configured true)`), a malicious first-caller can set nonsensical or adversarial `reward-cycle-length`/`prepare-cycle-length`/`first-burn-height`/`begin-pox5-reward-cycle` values before the intended deployer transaction executes. Since `bond-period-to-burn-height`/`bond-period-to-reward-cycle` (and downstream unlock-height computation for every staker/bond) are derived directly from these constants, a corrupted configuration can permanently desynchronize the mapping between bond periods and burn heights for the life of the contract (no re-initialization path exists), which can manifest as staked STX/sBTC being locked with an incorrect unlock schedule (permanently frozen, or unlockable far earlier/later than intended) — breaking the equality between "the reward cycle a staker/bond committed to" and "the reward cycle the contract believes is active." This is a "permanent freezing of staked STX or sBTC" / "unlocking value never locked" class impact under the given classification.

### Likelihood Explanation
On a live network this requires winning a mempool race against the boot/deploy transaction that calls `set-burnchain-parameters` for pox-5 — feasible for any observer since the call carries no special privilege and simply needs to land before the legitimate one, in the same window during which `pox-5.clar` is boot-deployed (per `boot/mod.rs`) but not yet configured.

### Recommendation
Restrict `set-burnchain-parameters` to a known, trusted principal (e.g., require `contract-caller` to be the boot/deploy principal or a designated admin var, mirroring the `is-eq contract-caller (var-get bond-admin)` pattern already used elsewhere in this contract), and/or perform this initialization atomically as part of the same deploy transaction so no window for front-running exists.

### Proof of Concept
1. Deploy/boot `pox-5.clar` (per the sequence in `boot/mod.rs`) so the contract exists but `configured` is still `false`.
2. Before the legitimate governance/deploy transaction calling `set-burnchain-parameters` is mined, submit a competing transaction from any unprivileged principal invoking `(contract-call? .pox-5 set-burnchain-parameters u0 u1 u1000000 u1)` (or any attacker-chosen values).
3. Because there is no caller check — only the `configured` guard — this transaction succeeds if it lands first, permanently setting `first-burnchain-block-height`, `pox-prepare-cycle-length`, `pox-reward-cycle-length`, `first-pox-5-reward-cycle`, and `first-bond-period-cycle` to the attacker's chosen values.
4. All subsequent `setup-bond`, `register-for-bond`, and unlock-height computations for every staker are now based on the attacker-controlled cycle/bond parameters, with no on-chain remediation possible since `set-burnchain-parameters` can never be called again.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L429-449)
```text
;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters
        (first-burn-height uint)
        (prepare-cycle-length uint)
        (reward-cycle-length uint)
        (begin-pox5-reward-cycle uint)
    )
    (begin
        (unwrap-panic (if (var-get configured)
            (err false)
            (ok true)
        ))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-prepare-cycle-length prepare-cycle-length)
        (var-set pox-reward-cycle-length reward-cycle-length)
        (var-set first-pox-5-reward-cycle begin-pox5-reward-cycle)
        (var-set first-bond-period-cycle begin-pox5-reward-cycle)
        (var-set configured true)
        (ok true)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L451-467)
```text
(define-public (set-bond-admin (new-admin principal))
    (let (
            (old-admin (var-get bond-admin))
            (result {
                old-admin: old-admin,
                new-admin: new-admin,
            })
        )
        ;; only bond admin can call this.
        (asserts! (is-eq contract-caller old-admin) ERR_UNAUTHORIZED)
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))
        (var-set bond-admin new-admin)
        (print (merge { topic: "set-bond-admin" } result))
        (ok result)
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L530-557)
```text
        )
        ;; only bond admin can call this.
        (asserts! (is-eq contract-caller (var-get bond-admin)) ERR_UNAUTHORIZED)

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; only can be called within 2 cycles of bond start
        (asserts!
            (or
                ;; prevent underflow
                (< bond-start-height
                    (* BOND_GAP_CYCLES (var-get pox-reward-cycle-length))
                )
                (<=
                    (- bond-start-height
                        (* BOND_GAP_CYCLES (var-get pox-reward-cycle-length))
                    )
                    burn-block-height
                )
            )
            ERR_CANNOT_SETUP_BOND_TOO_SOON
        )

        ;; only can be called before bond start
        (asserts! (< burn-block-height bond-start-height)
            ERR_CANNOT_SETUP_BOND_TOO_LATE
        )
```

**File:** contrib/core-contract-tests/tests/pox-5/pox-5-helpers.ts (L546-558)
```typescript
export function initPox5() {
  txOk(
    pox5.setBurnchainParameters({
      firstBurnHeight: 0n,
      prepareCycleLength: 10n,
      rewardCycleLength: REWARD_CYCLE_LENGTH,
      beginPox5RewardCycle: 1n,
    }),
    deployer,
  );
  txOk(pox5.setBondAdmin(deployer), POX5_BOOTSTRAP_ADMIN);
  txOk(pox5.setPauseAdmin(deployer), POX5_BOOTSTRAP_ADMIN);
}
```

**File:** stacks-node/src/tests/pox_5_integrations.rs (L448-453)
```rust
    // The pox-5 boot contract initializes its `bond-admin` data var to
    // `tx-sender`, which at boot deploy time is the unsignable boot
    // principal. Override it to a key we control so that `setup-bond` is
    // callable from the test (forbidden on mainnet).
    let bond_admin_sk = Secp256k1PrivateKey::random();
    let bond_admin_addr = tests::to_addr(&bond_admin_sk);
```
