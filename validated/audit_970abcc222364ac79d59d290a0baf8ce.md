This is a strong analog: `BLSPubkeyToRankMap::new` in `runtime/src/epoch_stakes.rs` builds the Alpenglow/BLS validator rank map by filtering out vote accounts with duplicate BLS pubkeys or duplicate node identity pubkeys, and accounts with zero stake, from the raw `epoch_vote_accounts_hash_map`.

### Title
Panic on empty BLS rank map when de-duplication filtering removes all stake - (File: runtime/src/epoch_stakes.rs)

### Summary
`BLSPubkeyToRankMap::new` computes `total_stake` by summing the stakes of only the vote accounts that survive de-duplication (unique BLS pubkey and unique node identity), then unwraps this into a `NonZero<u64>` via `.expect("total stakes should not be 0")` [1](#0-0) . If every entry in the epoch's `VoteAccountsHashMap` is filtered out — because they all collide on a duplicated BLS pubkey or duplicated node identity (as demonstrated by `test_bls_pubkey_rank_map_excludes_duplicate_bls_and_identity`) — the accumulated `total_stake` is `0` and the `expect()` panics [2](#0-1) . This mirrors the Carapace bug pattern: an aggregate "denominator" (`total_stake`/`totalSTokenUnderlying`) can be driven to zero by adversarial/edge-case input while the raw underlying set (`totalSupply`/vote accounts) is non-empty, and the code has no graceful zero-guard — it panics/reverts instead.

### Finding Description
`BLSPubkeyToRankMap` is built per-epoch from the raw `VoteAccountsHashMap`. The construction logic:
1. Skips zero-stake accounts (`NonZero::new(*stake)` returning `None`).
2. Skips accounts without a valid compressed BLS pubkey.
3. Counts occurrences of each `bls_pubkey_compressed` and each `node_pubkey`, then keeps only entries where **both** counts equal `1` [3](#0-2) .
4. Sums the stakes of the *surviving* entries and wraps this sum in `NonZero::new(...).expect("total stakes should not be 0")` [1](#0-0) .

If validators register vote accounts that collide on BLS pubkeys (e.g., multiple vote accounts reusing the same authorized-voter BLS key, or multiple vote accounts sharing a node identity — both of which are validator-controlled configuration choices, not protocol-enforced-unique at account-creation time) such that after filtering **no** entries remain, `total_stake` sums to `0` and the `.expect()` panics. This is directly analogous to the Carapace bug: the aggregate denominator (`totalSTokenUnderlying`/`_getExchangeRate()`) can become `0` through legitimate participant actions even though the underlying data set (`totalSupply`/raw vote accounts) is non-empty, and the code lacks a safe fallback path.

### Impact Explanation
`bls_pubkey_to_rank_map()` is a public accessor on `VersionedEpochStakes`/`EpochStakes`, lazily computed via `OnceLock` and used by the Alpenglow/votor consensus machinery to build BLS rank/threshold structures for the epoch. A panic here inside consensus-critical code paths (invoked identically by every node computing the same epoch's stakes) would crash the validator process. Because every node evaluating that epoch's `VoteAccountsHashMap` would hit the identical zero-total-stake condition deterministically, this is not an isolated single-node crash but a cluster-wide, epoch-boundary halt — validators repeatedly panicking/restarting when trying to compute BLS rank data for the affected epoch, which matches the "epoch-boundary halt" and "cross-node state divergence/crash" impact classes.

### Likelihood Explanation
Likelihood depends on whether it is realistically possible to get *zero* surviving entries after the dedup filter while the raw vote-account set is non-empty. This requires every vote account in the epoch to be disqualified by either (a) zero stake, (b) missing/invalid BLS pubkey, or (c) a BLS-pubkey or node-pubkey collision with another vote account. On a live mainnet-scale cluster with many independent validators, an "everyone collides" scenario is unlikely, but this code is exercised at Alpenglow migration/rollout and in smaller/test/private clusters (e.g., devnet, dev clusters, single-validator or few-validator setups) where BLS-key or node-identity misconfiguration by a subset of participants could plausibly zero out the survivor set. The repository's own test suite explicitly exercises and asserts this panic path (`test_multiple_vote_accounts_panics`, expecting `"total stakes should not be 0"`), confirming the condition is reachable and was a known-designed panic rather than a hardened invariant [2](#0-1) .

### Recommendation
Do not `.expect()`-panic when the filtered `total_stake` is zero. Instead:
- Return a `Result`/`Option` from `BLSPubkeyToRankMap::new` (or from `bls_pubkey_to_rank_map()`), allowing callers to handle the "no eligible BLS validators this epoch" case gracefully (e.g., fall back to disabling BLS/Alpenglow-specific consensus paths for that epoch, or treating it the same as `is_empty()`).
- Alternatively, guarantee at a higher level (e.g., during vote-account/epoch-stakes construction) that this condition cannot occur for any epoch that will actually reach BLS-dependent consensus code, and add an explicit, non-panicking short-circuit (mirroring the existing `is_empty()` check) before computing rank data.

### Proof of Concept
The existing test in the same file already demonstrates the exact panic condition — constructing `VersionedEpochStakes` from vote accounts that all collide on BLS pubkey or node identity and then calling `bls_pubkey_to_rank_map()`: [2](#0-1) 

Extending that same setup (e.g., using the duplicate-pubkey construction from `test_bls_pubkey_rank_map_excludes_duplicate_bls_and_identity`, but ensuring *all* entries collide rather than just some) reproduces the panic on any node that computes `bls_pubkey_to_rank_map()` for that epoch's stakes: `BLSPubkeyToRankMap::new` sums zero stake across zero surviving entries and hits `NonZero::new(0).expect("total stakes should not be 0")` [1](#0-0) , causing the calling validator process to panic/crash rather than fail gracefully.

### Citations

**File:** runtime/src/epoch_stakes.rs (L115-123)
```rust
        let mut keys_stake_entry_with_compressed: Vec<(BLSPubkeyStakeEntry, BLSPubkeyCompressed)> =
            candidates
                .into_iter()
                .filter_map(|(entry, bls_pubkey_compressed)| {
                    (bls_pubkey_counts[&bls_pubkey_compressed] == 1
                        && node_pubkey_counts[&entry.node_pubkey] == 1)
                        .then_some((entry, bls_pubkey_compressed))
                })
                .collect();
```

**File:** runtime/src/epoch_stakes.rs (L124-129)
```rust
        let total_stake = keys_stake_entry_with_compressed
            .iter()
            .fold(0u64, |stake, (entry, _)| {
                stake.saturating_add(entry.stake.get())
            });
        let total_stake = NonZero::new(total_stake).expect("total stakes should not be 0");
```

**File:** runtime/src/epoch_stakes.rs (L800-817)
```rust
    #[test]
    #[should_panic(expected = "total stakes should not be 0")]
    fn test_multiple_vote_accounts_panics() {
        agave_logger::setup();
        let num_nodes = 10;

        let vote_accounts_map = new_vote_accounts(num_nodes, 2, true);
        let node_id_to_stake_map = vote_accounts_map
            .keys()
            .enumerate()
            .map(|(index, node_id)| (*node_id, ((index + 1) * 100) as u64))
            .collect::<HashMap<_, _>>();
        let epoch_vote_accounts = new_epoch_vote_accounts(&vote_accounts_map, |node_id| {
            *node_id_to_stake_map.get(node_id).unwrap()
        });
        let epoch_stakes = VersionedEpochStakes::new_for_tests(epoch_vote_accounts.clone(), 0);
        epoch_stakes.bls_pubkey_to_rank_map();
    }
```
