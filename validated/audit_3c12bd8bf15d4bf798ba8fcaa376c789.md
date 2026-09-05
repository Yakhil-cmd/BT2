### Title
Reusable L1 Bitcoin lockup proofs allow double-counting of staked sats in `pox-5.clar` - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`register-for-bond` / `update-bond-registration` in `pox-5.clar` credit a staker's `sats-total` (and therefore signer/staker/total share weights for reward-slot and signer-set computation) based on a caller-supplied Bitcoin SPV proof of an L1 timelock output, validated by `validate-l1-lockup` [1](#0-0) . The only anti-replay check performed is against a `seen-outpoints` list that is local to the single call's fold accumulator [2](#0-1) , not a persistent, contract-wide registry of already-consumed `(txid, output-index)` outpoints.

### Finding Description
`validate-l1-lockup` checks:
- unlock height bounds,
- that the output's script matches the expected timelock script for this staker,
- that the amount matches the claimed amount,
- that the outpoint hasn't already appeared **within this same call's list** (`seen-outpoints`),
- that the supplied Bitcoin header is valid and the merkle proof links the tx to that header [3](#0-2) .

Nowhere in this function, or in any map I could locate via search (`seen-outpoints`, `get-reversed-txid`, `verify-block-header` all resolve only inside `pox-5.clar` with no companion persistent "used outpoints" map), is the outpoint checked against previously accepted registrations from *other* calls. Since `sum` (i.e., `sats-total`) from a validated lockup is then used to set `staker-shares-staked-for-cycle`, `signer-shares-staked-for-cycle`, and `total-shares-staked-for-cycle` [4](#0-3) , and total-sats staked feeds directly into `pox_5_make_signer_set`'s weight apportionment for the signer set [5](#0-4) , a staker (or colluding stakers) can submit the *same* already-proven L1 lockup transaction output in a second `register-for-bond`/`update-bond-registration` call (e.g., for a different bond index, or after `unstake`/rollover resets local staker-info) to be credited with the same locked sats a second time, without any additional BTC ever being locked.

### Impact Explanation
This breaks the equality the protocol depends on: total credited staked-sats (driving reward-slot/signer weight and reward accrual under `get-rewards`/`calculate-rewards`, which multiplies rewards by staked shares [6](#0-5) ) versus actual sats locked on Bitcoin. Double-counted shares directly inflate signer weight in the Nakamoto signer set and inflate a staker's share of pool sBTC rewards, i.e., "double-counting a commitment or reward" / "signing weight ... exceeding locked value" — matching the Critical/High impact bucket in the rules.

### Likelihood Explanation
The bug requires only an unprivileged staker to call `register-for-bond` twice (or register/roll into another bond index) presenting the identical, already-used L1 lockup proof data. No admin, miner, or signer key is required — the caller already possesses a valid SPV proof from their one real Bitcoin lock, and nothing on-chain in `pox-5.clar` prevents resubmission across separate transactions.

### Recommendation
Persist consumed `(txid, output-index)` outpoints in a contract-level map (not just the transient fold accumulator) and assert non-membership across all historical registrations, for the lifetime relevant to the lockup (or permanently), before crediting `sats-total`.

### Proof of Concept
1. Staker generates one real Bitcoin L1 timelock output for amount `A`, obtains header + merkle-proof data for it.
2. Staker calls `register-for-bond` with `bond-index: 0`, supplying the lockup proof; `validate-l1-lockup` accepts it, credits `A` sats to bond 0's shares.
3. Staker calls `register-for-bond`/`update-bond-registration` again with `bond-index: 1` (or same index after an `unstake`/rollover cycle), presenting the exact same `tx`/`header`/`leaf-hashes`/`output-index` proof. Because `seen-outpoints` resets per call and there is no persistent registry, `validate-l1-lockup` accepts it again, crediting `A` sats a second time.
4. Total staked sats recorded by the contract (and hence signer/staker weight and reward share) is now `2A`, while only `A` sats are actually locked on Bitcoin.

I was not able to fully rule out, within the tool-call budget available, whether some other, differently-named persistent map elsewhere in the contract (outside the greps I ran) tracks consumed outpoints; this should be double-checked before treating the finding as fully confirmed, but no such map was found in `pox-5.clar` in the areas I was able to inspect.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L786-805)
```text
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
        ;; NOT tear down the old bond's per-cycle shares/delegation (unlike
        ;; `update-bond-registration`, which removes then re-adds).
        (try! (add-staker-to-bond-cycles tx-sender signer bond-index first-reward-cycle
            BOND_LENGTH_CYCLES sats-total
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx false
        ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2031-2113)
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
        ;; verify merkle proof
        (asserts!
            (or
                (is-eq (get merkle-root block) txid) ;; true, if the transaction is the only transaction
                (verify-merkle-proof reversed-txid
                    (reverse-buff32 (get merkle-root block))
                    (get tx-index lockup) (get tx-count lockup)
                    (get leaf-hashes lockup)
                )
            )
            ERR_INVALID_MERKLE_PROOF
        )
        (ok {
            staker: (get staker accumulator),
            minimum-unlock-height: (get minimum-unlock-height accumulator),
            staker-unlock-bytes: (get staker-unlock-bytes accumulator),
            early-unlock-bytes: (get early-unlock-bytes accumulator),
            sum: (+ (get sum accumulator) (get amount output)),
            seen-outpoints: (unwrap-panic (as-max-len? (append seen-outpoints outpoint) u10)),
        })
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2135-2160)
```text
(define-read-only (get-rewards)
    (let (
            (cur-reserve (var-get reserve-balance))
            (total-staked-sbtc (get-total-sbtc-staked))
            (current-balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
        )
        (- current-balance total-staked-sbtc cur-reserve)
    )
)

;; Returns the total amount of newly received sBTC rewards
;; since the last rewards computation
(define-read-only (get-new-rewards)
    (let (
            (last-accounted-rewards (var-get last-accounted-rewards-only))
            (rewards-balance (get-rewards))
        )
        (- rewards-balance last-accounted-rewards)
    )
)

(define-public (calculate-rewards (bond-periods (list 6 uint)))
    (let (
            (last-calc (var-get last-reward-compute-height))
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L850-872)
```rust
            total_ustx_locked += entry.amount_ustx;

            signer_set
                .entry(entry.signer_key)
                .and_modify(|existing_entry| *existing_entry += entry.amount_ustx)
                .or_insert_with(|| entry.amount_ustx);
        }

        // Allocate `reward_slots` weight across signers in proportion to stake using the
        // a largest-remainder method:
        //
        // The threshold is `ceil(total / reward_slots)`.
        //
        // Flooring each signer's `stacked / threshold` assigns a base weight where the sum is `<= reward_slots`
        // (the ceil makes `total/threshold <= reward_slots`).
        //
        // This leaves some unassigned ("leftover") slots, which are handed out one-per-signer
        //  in descending fractional-remainder order (ties broken by pubkey-sort order).
        //
        // This avoids degenerate modes of the floor-and-drop scheme: when more than
        // `reward_slots` distinct signers hold roughly equal stake, every base weight floors to
        // 0, and without the leftover round the entire signer set could be dropped.
        let reward_slots = u128::from(pox_constants.reward_slots());
```
