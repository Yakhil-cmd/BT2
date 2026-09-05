### Title
Reused Bitcoin lockup outpoints allow unbacked sats to be credited to multiple pox-5 bonds - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond`'s L1-collateral path validates a Bitcoin timelock output via `verify-l1-lockups`/`validate-l1-lockup`, but the anti-replay protection ("seen-outpoints") only de-duplicates outpoints *within a single call's list of lockups*. There is no persistent, contract-wide record of Bitcoin `(txid, output-index)` pairs that have already been credited. A staker can therefore submit the exact same historical L1 lockup proof (same header, tx, merkle proof, output) to `register-for-bond` multiple times — across different `bond-index` registrations, or after the underlying BTC UTXO has already been spent/unlocked on Bitcoin — and have it accepted as valid collateral every time.

### Finding Description
`verify-l1-lockups` (stackslib/src/chainstate/stacks/boot/pox-5.clar:1985-2019) folds over the caller-supplied `outputs` list via `validate-l1-lockup`, threading a `seen-outpoints` accumulator that is initialized to `(list)` fresh on every call: [1](#0-0) 

`validate-l1-lockup` checks the timelock script hash, the amount, the block header, the merkle inclusion proof, and rejects a duplicate outpoint only if it is already in the *in-memory* `seen-outpoints` list built during that same call: [2](#0-1) 

None of these checks reference any map/var that persists previously-credited outpoints between transactions. `register-for-bond` calls `verify-l1-lockups` to compute `sats-total`, which becomes the staker's `amount-sats`/collateral basis for STX minimums, signer shares, and reward accrual: [3](#0-2) 

Because Bitcoin transaction proofs are self-contained historical facts (block header + merkle path + tx), they remain forever "valid" from the contract's point of view even after the referenced BTC output has since been spent (early-unlocked, or the staker's original bond already matured and they withdrew on L1). The contract has no way to tell if the sats are *currently* locked — it only re-verifies that they *were once* included in some Bitcoin block with a matching timelock script.

### Impact Explanation
An unprivileged staker can:
1. Create one real BTC timelock UTXO and use it once to register for bond A, receiving credited `sats-total`, staker shares, and reward eligibility.
2. Reuse the identical lockup proof (same txid/output-index/header/merkle proof) in a subsequent `register-for-bond` call for a different `bond-index` (e.g., a non-overlapping or later bond), or after unlocking/spending the BTC on L1, and pass all checks again because `seen-outpoints` never persists across transactions.

This produces sats credited to the protocol's accounting (`get-staker-custodied-sbtc`-equivalent bookkeeping, `staker-shares-staked-for-cycle`, signer delegated amounts, and bond reward-share weight) that are not backed by any currently-locked Bitcoin — i.e., "sats credited by an L1 proof that were never locked on Bitcoin," and simultaneously "double-counting a commitment" since the same BTC collateral can back more than one bond position/reward stream at once. This directly inflates a staker's/signer's effective locked sBTC weight and reward share (`calculate-bond-rewards` distributes sBTC proportional to `total-sats`), amounting to theft of sBTC rewards or reward-slot pollution with no real backing — a Critical-severity double-count of a commitment/reward.

### Likelihood Explanation
Any user who has ever created a valid L1 timelock output can trivially replay their historical Bitcoin proof data (which is public and permanently retrievable from the Bitcoin chain) into a second `register-for-bond` call. No signer/admin/oracle collusion, no race condition, and no special privilege is required — only knowledge of the previously-submitted proof data, which is visible in Stacks transaction history/logs.

### Recommendation
Persist consumed `(txid, output-index)` pairs (or a hash thereof) in a contract map keyed independent of `bond-index`/call, and reject `register-for-bond`/`verify-l1-lockups` calls that reference an outpoint already recorded as consumed by any prior registration, regardless of which bond or staker it was originally credited to. Consider also requiring proof that the referenced output is still *unspent* (not just once-included) at verification time, or require the lockup script's scheduled unlock height to still be in the future relative to the current burn height, which would at least prevent replay of already-matured (or forcibly early-unlocked) UTXOs.

### Proof of Concept
1. Staker Alice creates a valid Bitcoin timelock UTXO `U` (txid `T`, output index `0`) locking `S` sats, committing to Alice's `staker-unlock-bytes` and bond 0's `early-unlock-bytes`, per `construct-lockup-output-script`.
2. Alice calls `register-for-bond` for `bond-index 0` with `btc-lockup = (err [lockup for U])`. `verify-l1-lockups` validates `U` and credits `sats-total = S`; Alice becomes a bond-0 member with `amount-sats = S`.
3. Deployer opens `bond-index 6` (the next contiguous rollover bond). Before or independent of the roll-forward, Alice calls `register-for-bond` again for `bond-index 6` supplying the *same* lockup data for `U` (`txid T`, `output-index 0`, identical header/merkle proof/tx).
4. `validate-l1-lockup` re-validates the script hash, amount, header, and merkle proof for `U` — all pass again since `seen-outpoints` was reinitialized to `(list)` for this new call and no contract-level state remembers `U` was already used for bond 0.
5. Alice is now credited `sats-total = S` a second time for bond 6, receiving a second set of `staker-shares-staked-for-cycle` and reward eligibility for the SAME underlying `S` sats of Bitcoin collateral, without any additional BTC ever being locked.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L670-687)
```text
    (let (
            (signer (contract-of signer-manager))
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
            ;; Any bond the staker is currently a member of. Some value here
            ;; means this is a roll-over from an ending bond into a later one.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock).
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2004-2019)
```text
    (let (
            (bond (unwrap! (get-protocol-bond bond-index) ERR_BOND_NOT_FOUND))
            (accumulation (try! (fold validate-l1-lockup (get outputs lockups)
                (ok {
                    sum: u0,
                    staker: staker,
                    minimum-unlock-height: (get-bond-l1-unlock-height bond-index),
                    staker-unlock-bytes: (get staker-unlock-bytes lockups),
                    early-unlock-bytes: (get early-unlock-bytes bond),
                    seen-outpoints: (list),
                })
            )))
        )
        (ok (get sum accumulation))
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2031-2091)
```text
(define-private (validate-l1-lockup
        (lockup {
            height: uint,
            tx: (buff 100000),
            output-index: uint,
            header: (buff 80),
            leaf-hashes: (list 14 (buff 32)),
            tx-count: uint,
            tx-index: uint,
            amount: uint,
            unlock-burn-height: uint,
        })
        (accumulator-res (response {
            staker: principal,
            minimum-unlock-height: uint,
            staker-unlock-bytes: (buff 683),
            early-unlock-bytes: (buff 683),
            sum: uint,
            seen-outpoints: (list 10 {
                txid: (buff 32),
                output-index: uint,
            }),
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (block (try! (parse-block-header (get header lockup))))
            (unlock-burn-height (get unlock-burn-height lockup))
            (expected-script-hash (try! (construct-lockup-output-script (get staker accumulator)
                unlock-burn-height (get staker-unlock-bytes accumulator)
                (get early-unlock-bytes accumulator)
            )))
            (output (try! (get-bitcoin-tx-output? (get tx lockup) (get output-index lockup))))
            (reversed-txid (get txid output))
            (txid (reverse-buff32 reversed-txid))
            (outpoint {
                txid: txid,
                output-index: (get output-index lockup),
            })
            (seen-outpoints (get seen-outpoints accumulator))
        )
        (asserts! (>= unlock-burn-height (get minimum-unlock-height accumulator))
            ERR_INVALID_UNLOCK_HEIGHT
        )
        (asserts! (< unlock-burn-height BITCOIN_LOCKTIME_THRESHOLD)
            ERR_INVALID_UNLOCK_HEIGHT
        )
        (asserts! (is-eq (get script output) expected-script-hash)
            ERR_INVALID_LOCKUP_SCRIPT
        )
        (asserts! (is-eq (get amount output) (get amount lockup))
            ERR_INVALID_LOCKUP_AMOUNT
        )
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
        (asserts! (verify-block-header (get header lockup) (get height lockup))
            ERR_INVALID_BTC_HEADER
        )
```
