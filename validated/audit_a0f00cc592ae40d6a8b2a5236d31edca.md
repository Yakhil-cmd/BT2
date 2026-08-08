### Title
Unbounded per-epoch O(N) cost in `parse_epoch_vote_accounts` from attacker-created zero/low-stake vote accounts - ([File: runtime/src/epoch_stakes.rs])

### Summary
Any unprivileged user can create arbitrarily many vote accounts via `vote_instruction::create_account` paying only the one-time rent-exempt minimum, with no delegated stake required. Each such account is unconditionally added to the bank's `Stakes.vote_accounts` map and is iterated every epoch by `VersionedEpochStakes::parse_epoch_vote_accounts`, so the epoch-boundary cost paid by every validator scales linearly with attacker-created vote-account count rather than with meaningfully staked validators.

### Finding Description
`StakesCache::check_and_store` unconditionally inserts any correctly-sized, initialized, lamport-funded vote-program-owned account into `Stakes.vote_accounts` regardless of whether any stake is delegated to it: [1](#0-0) . The entry's stake starts at `0` unless a stake account is later delegated (`upsert_vote_account` computes stake from `delegated_stakes`, defaulting to `0`): [2](#0-1) .

At every epoch boundary, `Bank::update_epoch_stakes` builds a fresh `VersionedEpochStakes::new`, which calls `parse_epoch_vote_accounts` over the *entire* `epoch_vote_accounts` map: [3](#0-2) . The loop itself is `O(N)` over all entries — every entry incurs the iteration and `total_stake += *stake` cost before the `stake == 0` short-circuit (`continue`) skips the more expensive `vote_state_view()`/authorized-voter work: [4](#0-3) .

There is no cap anywhere in this path on the number of distinct vote-account pubkeys that can be tracked. Creating a vote account is a normal, permitted operation (no special authority needed — the attacker funds and owns the account), and the only cost is the one-time rent-exempt minimum balance for the vote-account size (`VoteStateV4::size_of()`), not a cost that scales with the recurring per-epoch validator work it induces. Because Solana accounts are rent-exempt (no ongoing rent once funded above the minimum), these zero-stake vote accounts persist indefinitely unless the attacker withdraws their own lamports — which they control and have no incentive to do. Hence the attacker pays a bounded, one-time cost to impose an unbounded, permanently recurring linear cost on every validator's `update_epoch_stakes` call, once per epoch, for as long as the accounts exist.

No signer/authority check, rent check, or epoch-boundary size cap intervenes: vote-account creation is intentionally permissionless, and `parse_epoch_vote_accounts` has no bound on `epoch_vote_accounts.len()`.

### Impact Explanation
Each epoch boundary, `update_epoch_stakes` (called on every validator) does `O(V)` work in `parse_epoch_vote_accounts`, where `V` is the total number of live vote accounts, including zero/near-zero-stake ones created solely by the attacker. Since this runs on every validator identically, this is a cluster-wide, cumulative, linear-in-attacker-spend slowdown of core epoch-boundary bank processing — not an RPC-only or single-node issue, and not bounded by any allowlist, cap, or fee scaling. Left unmitigated, sustained low-cost spam of vote-account creation degrades epoch-transition performance across the entire validator set, which falls into the resource-exhaustion / degraded-availability category rather than direct fund theft.

### Likelihood Explanation
Fully reachable by an ordinary unprivileged user: fund a `Keypair`, call `vote_instruction::create_account_with_config`/`create_account` with `Initialize`, repeat `V` times. No stake delegation, no validator/operator privileges, and no cluster control are required. The only barrier is the aggregate SOL cost of `V` rent-exempt minimums for the vote-account size, which is a one-time expenditure the attacker fully controls and amortizes — the resulting per-epoch cost to the cluster recurs indefinitely at no further cost to the attacker. This is straightforwardly reproducible in a unit/bench harness and does not require multiple RPC calls or leaked keys.

### Recommendation
Decouple the per-epoch iteration cost from the total number of ever-created vote accounts:
- Track/iterate only vote accounts with non-zero effective stake when building `node_id_to_vote_accounts` / `epoch_authorized_voters`, e.g. maintain a separate staked-only index in `VoteAccounts` (`runtime/src/stakes.rs`, `vote/src/vote_account.rs`) that is incrementally updated on stake delegate/undelegate rather than rebuilt by full scan every epoch.
- Alternatively, make `total_stake` accounting incremental (updated on each `add_stake`/`sub_stake` call in `VoteAccounts`) rather than recomputed by a full `O(N)` scan in `parse_epoch_vote_accounts` every epoch, and only iterate the (bounded) staked subset for the rest of the function.
- Consider charging an economically scaling cost (e.g., increasing rent/deposit) for vote-account creation, or periodically pruning long-lived zero-stake vote accounts, to bound `V` growth over time.

### Proof of Concept
```rust
// runtime/src/epoch_stakes.rs (bench-style test)
use {
    super::*,
    solana_vote::vote_account::VoteAccount,
    solana_vote_program::vote_state::create_v4_account_with_authorized,
    std::time::Instant,
};

fn bench_parse_epoch_vote_accounts(num_zero_stake_accounts: usize) -> std::time::Duration {
    let mut epoch_vote_accounts = VoteAccountsHashMap::default();
    // A handful of legitimately staked accounts.
    for _ in 0..10 {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let account = VoteAccount::try_from(create_v4_account_with_authorized(
            &node, &voter, [0u8; 32], &node, 0, &node, 0, &node, 100,
        )).unwrap();
        epoch_vote_accounts.insert(Pubkey::new_unique(), (100, account));
    }
    // Attacker-created zero-stake vote accounts (no delegated stake required).
    for _ in 0..num_zero_stake_accounts {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let account = VoteAccount::try_from(create_v4_account_with_authorized(
            &node, &voter, [0u8; 32], &node, 0, &node, 0, &node, 100,
        )).unwrap();
        epoch_vote_accounts.insert(Pubkey::new_unique(), (0, account)); // stake == 0
    }

    let start = Instant::now();
    let _ = VersionedEpochStakes::parse_epoch_vote_accounts(&epoch_vote_accounts, 0);
    start.elapsed()
}

#[test]
fn test_parse_epoch_vote_accounts_scales_with_attacker_created_accounts() {
    let t_1k = bench_parse_epoch_vote_accounts(1_000);
    let t_100k = bench_parse_epoch_vote_accounts(100_000);
    let t_1m = bench_parse_epoch_vote_accounts(1_000_000);

    // Assert unbounded linear scaling: no cap enforced upstream.
    assert!(t_100k > t_1k * 10);
    assert!(t_1m > t_100k * 5);
}
```
Expected result: runtime of `parse_epoch_vote_accounts` (and therefore `update_epoch_stakes`) grows linearly with `num_zero_stake_accounts`, demonstrating that the epoch-boundary cost is fully attacker-controllable and unbounded, contrary to the invariant that epoch-boundary work must be bounded.

### Citations

**File:** runtime/src/stakes.rs (L117-127)
```rust
        debug_assert_ne!(account.lamports(), 0u64);
        if solana_vote_program::check_id(owner) {
            if VoteStateVersions::is_correct_size_and_initialized(account.data()) {
                match VoteAccount::try_from(create_account_shared_data(account)) {
                    Ok(vote_account) => {
                        // drop the old account after releasing the lock
                        let _old_vote_account = {
                            let mut stakes = self.0.write().unwrap();
                            stakes.upsert_vote_account(pubkey, vote_account)
                        };
                    }
```

**File:** runtime/src/stakes.rs (L603-618)
```rust
    fn upsert_vote_account(
        &mut self,
        vote_pubkey: &Pubkey,
        vote_account: VoteAccount,
    ) -> Option<VoteAccount> {
        debug_assert_ne!(vote_account.lamports(), 0u64);

        let calculate_delegated_stake = || {
            self.delegated_stakes
                .get(vote_pubkey)
                .copied()
                .unwrap_or_default()
        };
        self.vote_accounts
            .insert(*vote_pubkey, vote_account, calculate_delegated_stake)
    }
```

**File:** runtime/src/epoch_stakes.rs (L269-283)
```rust
impl VersionedEpochStakes {
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    pub(crate) fn new(stakes: SerdeStakesToStakeFormat, leader_schedule_epoch: Epoch) -> Self {
        let stakes = EpochStakes::from(stakes);
        let epoch_vote_accounts = stakes.vote_accounts();
        let (total_stake, node_id_to_vote_accounts, epoch_authorized_voters) =
            Self::parse_epoch_vote_accounts(epoch_vote_accounts.as_ref(), leader_schedule_epoch);
        Self::Current {
            stakes,
            total_stake,
            node_id_to_vote_accounts: Arc::new(node_id_to_vote_accounts),
            epoch_authorized_voters: Arc::new(epoch_authorized_voters),
            bls_pubkey_to_rank_map: OnceLock::new(),
        }
    }
```

**File:** runtime/src/epoch_stakes.rs (L369-396)
```rust
    fn parse_epoch_vote_accounts(
        epoch_vote_accounts: &VoteAccountsHashMap,
        leader_schedule_epoch: Epoch,
    ) -> (u64, NodeIdToVoteAccounts, EpochAuthorizedVoters) {
        let mut node_id_to_vote_accounts: NodeIdToVoteAccounts = HashMap::new();
        let mut epoch_authorized_voters: EpochAuthorizedVoters = HashMap::new();
        let mut total_stake: u64 = 0;

        for (key, (stake, account)) in epoch_vote_accounts.iter() {
            total_stake += *stake;

            if *stake == 0 {
                continue;
            }

            let vote_state = account.vote_state_view();

            if let Some(authorized_voter) = vote_state.get_authorized_voter(leader_schedule_epoch) {
                let node_vote_accounts = node_id_to_vote_accounts
                    .entry(*vote_state.node_pubkey())
                    .or_default();

                node_vote_accounts.total_stake += stake;
                node_vote_accounts.vote_accounts.push(*key);

                epoch_authorized_voters.insert(*key, *authorized_voter);
            }
        }
```
