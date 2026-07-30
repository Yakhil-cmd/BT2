[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** crates/sui-core/src/stake_aggregator.rs (L64-77)
```rust
        match self.data.entry(authority) {
            Entry::Occupied(oc) => {
                return InsertResult::Failed {
                    error: SuiErrorKind::StakeAggregatorRepeatedSigner {
                        signer: authority,
                        conflicting_sig: oc.get() != &s,
                    }
                    .into(),
                };
            }
            Entry::Vacant(va) => {
                va.insert(s);
            }
        }
```

**File:** crates/sui-core/src/stake_aggregator.rs (L126-151)
```rust
    pub fn insert<T: Message + Serialize>(
        &mut self,
        envelope: Envelope<T, AuthoritySignInfo>,
    ) -> InsertResult<AuthorityQuorumSignInfo<STRENGTH>> {
        let (data, sig) = envelope.into_data_and_sig();
        if self.committee.epoch != sig.epoch {
            return InsertResult::Failed {
                error: SuiErrorKind::WrongEpoch {
                    expected_epoch: self.committee.epoch,
                    actual_epoch: sig.epoch,
                }
                .into(),
            };
        }
        match self.insert_generic(sig.authority, sig) {
            InsertResult::QuorumReached(_) => {
                match AuthorityQuorumSignInfo::<STRENGTH>::new_from_auth_sign_infos(
                    self.data.values().cloned().collect(),
                    self.committee(),
                ) {
                    Ok(aggregated) => {
                        match aggregated.verify_secure(
                            &data,
                            Intent::sui_app(T::SCOPE),
                            self.committee(),
                        ) {
```

**File:** crates/sui-core/src/stake_aggregator.rs (L359-374)
```rust
    pub fn insert(
        &mut self,
        authority: AuthorityName,
        k: K,
    ) -> InsertResult<&HashMap<AuthorityName, ()>> {
        let agg = self
            .stake_maps
            .entry(k)
            .or_insert_with(|| StakeAggregator::new(self.committee.clone()));

        if !agg.contains_key(&authority) {
            *self.votes_per_authority.entry(authority).or_default() += 1;
        }

        agg.insert_generic(authority, ())
    }
```

**File:** crates/sui-core/src/stake_aggregator.rs (L392-425)
```rust
#[test]
fn test_votes_per_authority() {
    let (committee, _) = Committee::new_simple_test_committee();
    let authorities: Vec<_> = committee.names().copied().collect();

    let mut agg: GenericMultiStakeAggregator<&str, true> =
        GenericMultiStakeAggregator::new(Arc::new(committee));

    // 1. Inserting an `authority` and a `key`, and then checking the number of votes for that `authority`.
    let key1: &str = "key1";
    let authority1 = authorities[0];
    agg.insert(authority1, key1);
    assert_eq!(agg.votes_for_authority(authority1), 1);

    // 2. Inserting the same `authority` and `key` pair multiple times to ensure votes aren't incremented incorrectly.
    agg.insert(authority1, key1);
    agg.insert(authority1, key1);
    assert_eq!(agg.votes_for_authority(authority1), 1);

    // 3. Checking votes for an authority that hasn't voted.
    let authority2 = authorities[1];
    assert_eq!(agg.votes_for_authority(authority2), 0);

    // 4. Inserting multiple different authorities and checking their vote counts.
    let key2: &str = "key2";
    agg.insert(authority2, key2);
    assert_eq!(agg.votes_for_authority(authority2), 1);
    assert_eq!(agg.votes_for_authority(authority1), 1);

    // 5. Verifying that inserting different keys for the same authority increments the vote count.
    let key3: &str = "key3";
    agg.insert(authority1, key3);
    assert_eq!(agg.votes_for_authority(authority1), 2);
}
```
