### Title
Missing global replay protection for L1 Bitcoin lockup outpoints allows the same BTC lock to be double-credited across multiple `register-for-bond` calls - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
This is a structural analog of the Multipool `fee0`/`fee1` bug: both bugs stem from computing/validating a "before vs. after" or "already-seen" state using a scope that is too narrow (per-call instead of global), letting an attacker replay or accrue state that the protocol assumes is unique/consumed. In Multipool, `tokensOwed*Before/After` were scoped per-call and missed fees accrued by third-party mints. In pox-5, the duplicate-outpoint guard for L1 Bitcoin lockup proofs (`seen-outpoints`) is scoped only to the single `verify-l1-lockups`/`validate-l1-lockup` fold invoked inside one `register-for-bond` call, with no persistent, contract-wide record of which Bitcoin outpoints have already been credited toward a bond.

### Finding Description
`register-for-bond` accepts a `btc-lockup` argument that, on the L1 path, is verified by `verify-l1-lockups` [1](#0-0) , which folds over the caller-supplied list of outputs via `validate-l1-lockup` [2](#0-1) .

The only duplicate-detection mechanism is the `seen-outpoints` list built up and checked with `(is-none (index-of? seen-outpoints outpoint))` [3](#0-2) . This list is initialized fresh as `(list)` at the start of every single `verify-l1-lockups` call [4](#0-3)  and is discarded once the call returns — it is never persisted to a contract-level map (e.g. a `used-l1-outpoints` map keyed by txid/output-index). A codebase-wide search for any such persistent record (`used-l1-outpoints`, `outpoint-used`, `l1-lockup-registry`, etc.) returned no matches.

Consequently, `validate-l1-lockup` only guarantees "this specific transaction doesn't list the same outpoint twice," not "this outpoint has never before been used to back a bond membership." The remaining checks — script-hash match, amount match, unlock-height bound, valid Bitcoin header, and valid merkle proof — are all satisfiable repeatedly for the exact same real, already-existing Bitcoin transaction output, since they only prove that the output exists and matches the expected timelock script; they do not prove exclusivity of use within the pox-5 contract's accounting.

This breaks the equality the protocol needs to hold: `total sats credited to bonds via L1 proofs == total sats actually and currently locked on Bitcoin`. An attacker can create a single legitimate L1 timelock UTXO and present the identical proof in multiple separate `register-for-bond` calls (e.g. across different `bond-index` values, or after the original bond membership ends/rolls over) to be credited the same `amount` (`sats-total`) more than once, without any additional BTC ever being locked.

### Impact Explanation
This maps to the explicitly in-scope Critical category "sats credited by an L1 proof that were never locked on Bitcoin" and "double-counting a commitment or reward." Sats credited via `verify-l1-lockups` feed directly into `sats-total`, which determines the staker's bond share/weight and thus their portion of sBTC bond rewards computed in `calculate-bond-rewards`/`get-rewards` [5](#0-4) , and their standing in the signer/reward-set computations that consume pox-5 stake data (`pox_5_compute_and_update_signers`) [6](#0-5) . Double-crediting one BTC lock lets an attacker claim reward shares, signing weight, and reward-slot standing far in excess of BTC actually and currently locked — theft of reserve/pool rewards from other honest stakers and unbacked "minting" of stacking credit.

### Likelihood Explanation
Exploitation only requires possessing one valid L1 timelock output matching the pox-5 script construction (`construct-lockup-output-script`) and re-submitting the SPV/merkle proof for that already-mined Bitcoin transaction in a second (or further) unprivileged `register-for-bond` transaction. No admin, miner, or other user's key is required; all inputs (`tx`, `header`, `leaf-hashes`, etc.) are public once the Bitcoin transaction is confirmed, so the proof can be freely reused. The only friction is finding an eligible `bond-index`/timing where a second registration is still permitted (e.g. a new bond, or after the staker's prior bond ends), which is normal usage, not a privileged state.

### Recommendation
Add a persistent, contract-level map (e.g. `used-l1-outpoints: {txid, output-index} -> bool` or -> `bond-index`/`staker`) that is checked and set inside `validate-l1-lockup`/`verify-l1-lockups`, rejecting any outpoint that has already been credited toward any current or past bond membership, instead of relying solely on the call-scoped `seen-outpoints` list. Optionally, tie the persisted record to the lockup's `unlock-burn-height` so it can be cleared/reused only once the timelock is confirmed to have actually unlocked and the corresponding bond membership was properly retired.

### Proof of Concept
1. Attacker creates and confirms one Bitcoin transaction output locked with the pox-5 timelock script for `staker = attacker`, `unlock-burn-height = H`, amount = `X` sats.
2. Attacker calls `register-for-bond(bond-index = A, ..., btc-lockup = err(...outputs: [that tx output]...))`. `verify-l1-lockups` validates it and credits `sats-total = X` toward bond `A`'s membership. [7](#0-6) 
3. Later (e.g. after bond `A`'s membership ends, or using a different `bond-index = B` the attacker is also allow-listed for), attacker calls `register-for-bond(bond-index = B, ..., btc-lockup = err(...same tx output...))` with the identical proof.
4. Because `seen-outpoints` is re-initialized to `(list)` for this new call [4](#0-3) , none of the assertions in `validate-l1-lockup` fail — the outpoint is not in this call's `seen-outpoints`, the script/amount/height/header/merkle checks all pass again — and `sats-total = X` is credited a second time, backing a second bond membership from the same, single, still-existing BTC lock.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L642-690)
```text
(define-public (register-for-bond
        (bond-index uint)
        (signer-manager <signer-manager-trait>)
        (amount-ustx uint)
        ;; Their BTC lockup info. If the response is `ok`, then
        ;; this is a list of outputs corresponding to their timelocks.
        ;; If the response is `err`, this is the amount of sBTC (in sats)
        ;; that they want to lock.
        (btc-lockup (response {
            outputs: (list 10
                {
                    height: uint,
                    tx: (buff 100000),
                    output-index: uint,
                    header: (buff 80),
                    leaf-hashes: (list 14 (buff 32)),
                    tx-count: uint,
                    tx-index: uint,
                    amount: uint,
                    unlock-burn-height: uint,
                }
            ),
            staker-unlock-bytes: (buff 683),
        }
            uint
        ))
        (signer-calldata (optional (buff 500)))
    )
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
            ;; Any STX-only stake the staker has. Present means this
            ;; `register-for-bond` is a roll-over from an ending stx-only
            ;; stake into a bond.
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1984-2019)
```text
(define-private (verify-l1-lockups
        (staker principal)
        (bond-index uint)
        (lockups {
            outputs: (list 10
                {
                    height: uint,
                    tx: (buff 100000),
                    output-index: uint,
                    header: (buff 80),
                    leaf-hashes: (list 14 (buff 32)),
                    tx-count: uint,
                    tx-index: uint,
                    amount: uint,
                    unlock-burn-height: uint,
                }
            ),
            staker-unlock-bytes: (buff 683),
        })
    )
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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2134-2156)
```text
;; Returns the total balance of rewards received by the contract
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
```

**File:** stackslib/src/chainstate/nakamoto/signer_set.rs (L744-761)
```rust
    fn pox_5_compute_and_update_signers(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
        _current_calculation_btc_height: u32,
        _current_epoch: &StacksEpochId,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        // Build the `(signer_key, amount_ustx)` pair stream
        let mut entries = Self::pox_5_stake_entries(clarity, reward_cycle, pox_contract)?;
        let Pox5SignerSetOutput {
            signer_set,
            pox_ustx_threshold,
        } = Self::pox_5_make_signer_set(&mut entries, pox_constants)?;
```
